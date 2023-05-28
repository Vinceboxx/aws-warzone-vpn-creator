import sys
import os
import tkinter as tk
from tkinter.ttk import Combobox
from tkinter import messagebox
import configparser
import boto3
import getpass

access_key_entry = None
secret_key_entry = None
region_entry = None

def get_latest_ami_with_openvpn(region='us-east-1'):
    ec2_client = boto3.client('ec2', region_name=region)

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

# Eseguire la funzione per ottenere l'AMI più recente con "OpenVPN" nel nome
latest_ami_id = get_latest_ami_with_openvpn()

def create_ec2_instance(access_key, secret_key, region):
    ec2_client = boto3.client('ec2',
                              aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key,
                              region_name=region)

    # Creazione dell'istanza EC2
    response = ec2_client.run_instances(
        ImageId=get_latest_ami_with_openvpn(region=region),  # Inserire l'ID dell'AMI di OpenSSH Server
        InstanceType='t3.micro',
        MinCount=1,
        MaxCount=1
    )

    instance_id = response['Instances'][0]['InstanceId']
    return instance_id

def get_aws_credentials():
    config = configparser.ConfigParser()
    config_file = os.path.expanduser('~/.aws/credentials')
    config.read(config_file)

    if 'default' in config:
        return config['default'].get('aws_access_key_id'), config['default'].get('aws_secret_access_key')
    else:
        return None, None

def get_aws_regions():
    config = configparser.ConfigParser()
    config_file = os.path.expanduser('~/.aws/config')
    config.read(config_file)

    regions = []
    for section in config.sections():
        if section.startswith('profile '):
            region = config[section].get('region')
            if region:
                regions.append(region)

    return regions


def get_all_aws_regions():
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_regions()
    regions = [region['RegionName'] for region in response['Regions']]
    return regions



def get_ec2_instances(access_key, secret_key, region):
    ec2_client = boto3.client('ec2',
                              aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key,
                              region_name=region)

    response = ec2_client.describe_instances()
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instances.append(instance)

    return instances

def update_instance_status(access_key, secret_key, region):
    instances = get_ec2_instances(access_key, secret_key, region)
    for instance in instances:
        instance_id = instance['InstanceId']
        state = instance['State']['Name']
        public_ip = instance.get('PublicIpAddress')
        instance_text = f"Instance ID: {instance_id}\nState: {state}\nPublic IP: {public_ip}"
        if instance_id not in instance_buttons:
            instance_button = tk.Button(root, text=instance_text, state=tk.DISABLED)
            instance_button.grid(sticky="W")
            instance_buttons[instance_id] = instance_button
        else:
            instance_button = instance_buttons[instance_id]
            instance_button.config(text=instance_text)

def start_instance(access_key, secret_key, region, instance_id):
    ec2_client = boto3.client('ec2',
                              aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key,
                              region_name=region)
    ec2_client.start_instances(InstanceIds=[instance_id])
    messagebox.showinfo("Success", f"Instance {instance_id} started")

def stop_instance(access_key, secret_key, region, instance_id):
    ec2_client = boto3.client('ec2',
                              aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key,
                              region_name=region)
    ec2_client.stop_instances(InstanceIds=[instance_id])
    messagebox.showinfo("Success", f"Instance {instance_id} stopped")

def terminate_instance(access_key, secret_key, region, instance_id):
    ec2_client = boto3.client('ec2',
                              aws_access_key_id=access_key,
                              aws_secret_access_key=secret_key,
                              region_name=region)
    ec2_client.terminate_instances(InstanceIds=[instance_id])
    messagebox.showinfo("Success", f"Instance {instance_id} terminated")

def run_gui():
    access_key, secret_key = get_aws_credentials()
    regions = get_all_aws_regions()

    if access_key and secret_key:
        root = tk.Tk()
        root.title("AWS EC2 Manager")

        access_key_label = tk.Label(root, text="Access Key:")
        access_key_label.grid(sticky="W")
        access_key_entry = tk.Entry(root, show="*")
        access_key_entry.grid(sticky="W")

        secret_key_label = tk.Label(root, text="Secret Key:")
        secret_key_label.grid(sticky="W")
        secret_key_entry = tk.Entry(root, show="*")
        secret_key_entry.grid(sticky="W")

        region_label = tk.Label(root, text="Region:")
        region_label.grid(sticky="W")
        region_combobox = tk.ttk.Combobox(root, values=regions, state="readonly")
        region_combobox.grid(sticky="W")

        def create_ec2_from_input():
            access_key = access_key_entry.get()
            secret_key = secret_key_entry.get()
            region = region_combobox.get()
            create_ec2_instance(access_key, secret_key, region)

        create_button = tk.Button(root, text="Create EC2 Instance", command=create_ec2_from_input)
        create_button.grid(sticky="W")

        update_button = tk.Button(root, text="Update Instances", command=lambda: update_instance_status(access_key, secret_key, region_combobox.get()))
        update_button.grid(sticky="W")

        root.mainloop()
    else:
        print("AWS credentials not found. Please configure your credentials file.")

def run_cli():
    access_key, secret_key = get_aws_credentials()
    regions = get_all_aws_regions()

    if not access_key or not secret_key:
        print("AWS credentials not found. Please configure your credentials file.")
        return

    print("Available regions:")
    for i, region in enumerate(regions, start=1):
        print(f"{i}. {region}")

    region_index = int(input("Select a region (enter the corresponding number): ")) - 1
    if region_index < 0 or region_index >= len(regions):
        print("Invalid region selection.")
        return

    region = regions[region_index]

    print(f"\nSelected region: {region}")

    while True:
        print("\n1. Create EC2 Instance")
        print("2. Update Instances")
        print("3. Start Instance")
        print("4. Stop Instance")
        print("5. Terminate Instance")
        print("6. Exit")

        choice = input("Select an option (enter the corresponding number): ")

        if choice == "1":
            create_ec2_instance(access_key, secret_key, region)
        elif choice == "2":
            update_instance_status(access_key, secret_key, region)
        elif choice == "3":
            instance_id = input("Enter the Instance ID: ")
            start_instance(access_key, secret_key, region, instance_id)
        elif choice == "4":
            instance_id = input("Enter the Instance ID: ")
            stop_instance(access_key, secret_key, region, instance_id)
        elif choice == "5":
            instance_id = input("Enter the Instance ID: ")
            terminate_instance(access_key, secret_key, region, instance_id)
        elif choice == "6":
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        run_gui()
    else:
        run_cli()