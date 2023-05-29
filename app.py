import os
import boto3
from botocore.exceptions import ClientError
from flask import Flask, render_template, request, send_file
import paramiko
import time

app = Flask(__name__)

# Configurazione del client AWS
session = boto3.Session(profile_name='default')
ec2_client = session.client('ec2')
ssm_client = session.client('ssm')

# Ottieni le credenziali dall'ambiente o dai profili AWS
aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_region = os.getenv('AWS_DEFAULT_REGION')


# Pagina principale
@app.route('/')
def index():
    instances = get_instances()
    free_tier_remaining = get_free_tier_remaining()
    regions = get_available_regions()

    return render_template('index.html', instances=instances, free_tier_remaining=free_tier_remaining, regions=regions)


# Ottieni tutte le istanze EC2 in esecuzione in tutte le regioni
def get_instances():
    instances = []

    # Ottieni la lista di tutte le regioni
    ec2_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    for region in ec2_regions:
        ec2 = session.client('ec2', region_name=region)
        response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'stopping']}])

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_details = {
                    'instance_id': instance['InstanceId'],
                    'instance_state' : instance['State']['Name'],
                    'state_reason' : ec2.describe_instance_status(InstanceIds=[instance['InstanceId']])['InstanceStatuses'][0]['InstanceStatus']['Status'],
                    'public_ip': instance.get('PublicIpAddress', 'N/A'),
                    'ami_id': instance['ImageId'],
                    'ami_name': get_ami_name(instance['ImageId'], region)[:21],
                    'region': region
                }
                instances.append(instance_details)

    return instances

def get_instance(instance_id, region):
    instances = []

    ec2 = session.client('ec2', region_name=region)
    response = ec2.describe_instances(Filters=[
        {'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'stopping']},
        {'Name': 'instance-id', 'Values': [instance_id]}
        ])

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_details = {
                'instance_id': instance['InstanceId'],
                'instance_state' : instance['State']['Name'],
                'state_reason' : instance.get('StateTransitionReason', ''),
                'public_ip': instance.get('PublicIpAddress', 'N/A'),
                'ami_id': instance['ImageId'],
                'ami_name': get_ami_name(instance['ImageId'], region)[:21],
                'region': region
            }
            instances.append(instance_details)

    return instances


# Ottieni il nome dell'AMI dato il suo ID
def get_ami_name(ami_id, region):
    ec2_client = session.client('ec2', region_name=region)
    response = ec2_client.describe_images(ImageIds=[ami_id])
    return response['Images'][0]['Name']


# Scarica il file di connessione per l'istanza OpenVPN
@app.route('/download/<instance_id>')
def download_vpn_config(instance_id):
    # Verifica che l'istanza esista e sia una istanza OpenVPN
    vpn_instance = next((instance for instance in get_vpn_instances() if instance['instance_id'] == instance_id), None)
    if vpn_instance:
        # Genera il file di configurazione OpenVPN e lo salva come temp.ovpn
        generate_vpn_config(instance_id)
        return send_file('temp.ovpn', as_attachment=True, attachment_filename='vpn_config.ovpn')

    return 'Instance not found or not an OpenVPN server'


# Crea una nuova istanza OpenVPN Server
@app.route('/create_instance',  methods=['POST'])
def create_vpn_instance():
    region = request.form.get('region')
    # Ottieni l'AMI più recente per OpenVPN dal marketplace
    ami_id = get_latest_ami_with_openvpn(region_name=region)
    ec2 = session.resource('ec2', region_name=region)

    # Nome del security group da cercare o creare
    security_group_name = 'OVPNSecGroup'
    security_group_id = create_security_group(security_group_name, region)

    key_pair_name = f'vpn-key-pair-{region}'
    private_key_path = f'./ssh_keys/vpn-key-pair-{region}.pem'

    if not os.path.exists(private_key_path):

        ec2_key_pair = ec2.create_key_pair(KeyName=key_pair_name)

        # Salva la chiave privata in un file
        with open(private_key_path, 'w') as f:
            f.write(ec2_key_pair.key_material)

        # Imposta le autorizzazioni del file della chiave privata
        os.chmod(private_key_path, 0o400)

    # Crea l'istanza EC2 utilizzando l'AMI
    
    instance = ec2.create_instances(
        ImageId=ami_id, 
        InstanceType='t3.micro', 
        MinCount=1, 
        MaxCount=1,
        KeyName=key_pair_name,
        SecurityGroupIds=[security_group_id]
        )[0]

    # Configura automaticamente il routing del traffico dal client
    configure_vpn_routing(instance.id)

    return 'New OpenVPN instance created'

def create_security_group(security_group_name, region):
    ec2_client = session.client('ec2', region_name=region)

    # Verifica se il security group esiste già
    response = ec2_client.describe_security_groups(
        Filters=[
            {'Name': 'group-name', 'Values': [security_group_name]}
        ]
    )

    if response['SecurityGroups']:
        # Il security group esiste già, utilizza l'ID esistente
        security_group_id = response['SecurityGroups'][0]['GroupId']
    else:
        # Il security group non esiste, creane uno nuovo
        response = ec2_client.create_security_group(
            GroupName=security_group_name,
            Description='Security group for OpenVPN Seriver'
        )
        security_group_id = response['GroupId']

        # Aggiungi le regole di ingresso al security group
        ec2_client.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 943,
                    'ToPort': 943,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 945,
                    'ToPort': 945,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'udp',
                    'FromPort': 1194,
                    'ToPort': 1194,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
    return security_group_id



@app.route('/initialize_server', methods=['POST'])
def initialize_server():
    instance_id = request.form['instance_id']
    region = request.form['region']
    instance = get_instance(instance_id, region)[0]

    commands = ['sudo ovpn-init --ec2', 'yes', 'yes', '1', 'secp384r1', 'secp384r1', 'secp384r1', '943', '443', 'yes', 'no', 'yes', 'yes', '\n', '\n']

    commands = ['whoami']
    execute_ssh_commands(instance['public_ip'], 'openvpnas', f'./ssh_keys/vpn-key-pair-{region}.pem', commands)

    return 'Instance initialized successfully'


# Ottieni l'AMI più recente per OpenVPN dal marketplace
def get_latest_openvpn_ami(region_name):
    ec2_client = boto3.client('ec2', region_name=region_name)
    response = ec2_client.describe_images(
        Owners=['aws-marketplace'],
        Filters=[{'Name': 'product-code', 'Values': ['your-openvpn-product-code']}],
        SortBy='CreationDate',
        SortOrder='descending',
        MaxResults=1
    )
    return response['Images'][0]['ImageId']


# Configura automaticamente il routing del traffico dal client per l'istanza OpenVPN
def configure_vpn_routing(instance_id):
    # Esegui le operazioni necessarie per la configurazione automatica del routing
    # utilizzando l'istanza OpenVPN identificata da instance_id
    pass

def get_latest_ami_with_openvpn(region_name='us-east-1'):
    ec2_client = boto3.client('ec2', region_name=region_name)

    # Ottenere la lista di AMI del Marketplace che contengono "OpenVPN" nel nome
    response = ec2_client.describe_images(
        Owners=['aws-marketplace'],
        Filters=[
            {
                'Name': 'name',
                'Values': ['*OpenVPN*']
            }
        ]
    )

    # Ordinare le AMI per data di creazione in ordine decrescente
    sorted_images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)

    if sorted_images:
        latest_ami_id = sorted_images[0]['ImageId']
        return latest_ami_id

    return None

def get_available_regions():
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_regions()
    regions = [region['RegionName'] for region in response['Regions']]
    return regions

# Ottieni il conteggio rimanente della free tier delle istanze EC2
def get_free_tier_remaining():
    billing_client = session.client('ce')

    try:
        response = billing_client.get_cost_and_usage(
            TimePeriod={
                'Start': '2023-01-01',
                'End': '2023-12-31'
            },
            Granularity='MONTHLY',
            Metrics=[
                'UsageQuantity'
            ],
            Filter={
                'And': [
                    {
                        'Dimensions': {
                            'Key': 'USAGE_TYPE_GROUP',
                            'Values': [
                                'EC2: Running Hours'
                            ]
                        }
                    },
                    {
                        'Dimensions': {
                            'Key': 'OPERATION',
                            'Values': [
                                'RunInstances'
                            ]
                        }
                    }
                ]
            }
        )

        free_tier_usage = response['ResultsByTime'][0]['Groups'][0]['Metrics']['UsageQuantity']['Amount']
        free_tier_remaining = 750 - float(free_tier_usage)

        return free_tier_remaining
    except ClientError as e:
        return None

def execute_ssh_commands(instance_public_ip, username, private_key_path, commands):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(instance_public_ip, username=username, key_filename=private_key_path)
        for command in commands:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode('utf-8')
            print(f'Output of command "{command}":')
            print(output)
            print('---')
            time.sleep(1)
    finally:
        ssh.close()


@app.route('/start-instance', methods=['POST'])
def startInstance():
    instance_id = request.form['instance_id']
    region = request.form['region']
    ec2_client = session.client('ec2', region_name=region)

    # Avvia l'istanza specificata
    ec2_client.start_instances(InstanceIds=[instance_id])

    return 'Instance started successfully'


@app.route('/stop-instance', methods=['POST'])
def stopInstance():
    instance_id = request.form['instance_id']
    region = request.form['region']
    ec2_client = session.client('ec2', region_name=region)

    # Ferma l'istanza specificata
    ec2_client.stop_instances(InstanceIds=[instance_id])

    return 'Instance stopped successfully'


@app.route('/terminate-instance', methods=['POST'])
def terminateInstance():
    instance_id = request.form['instance_id']
    region = request.form['region']
    ec2_client = session.client('ec2', region_name=region)

    # Termina l'istanza specificata
    ec2_client.terminate_instances(InstanceIds=[instance_id])

    return 'Instance terminated successfully'

@app.route('/instance-status/<instance_id>')
def get_instance_status(instance_id):
    # Logica per ottenere lo stato aggiornato dell'istanza specifica
    instance_status = get_instance_status_from_id(instance_id)
    
    # Restituisci il valore di instance_status come una risposta JSON
    return jsonify(instance_status=instance_status)


if __name__ == '__main__':
    app.run()