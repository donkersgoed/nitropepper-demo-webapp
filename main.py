"""Example NitroPepper web application."""

import socket
import json

import boto3
import requests
from flask import Flask, request

REGION = 'eu-central-1'
ENCLAVE_CID = 6
ENCLAVE_PORT = 5000
KMS_ALIAS = 'alias/nitropepper-cmk'
DYNAMODB_TABLE = 'nitropepper-users'

dynamodb = boto3.resource('dynamodb', region_name=REGION)
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    """Process user login."""
    username = request.form.get('username')
    password = request.form.get('password')

    try:
        ddb_user_data = ddb_fetch_user_data(username)
    except ValueError:
        # This would normally return {'success': False } to
        # prevent user enumeration.
        return {
            'error': f'User {username} not found'
        }

    password_hash = ddb_user_data['password_hash']
    encrypted_pepper = ddb_user_data['encrypted_pepper']
    password_valid = nitro_verify_user_credentials(password, password_hash, encrypted_pepper)
    if not password_valid['success']:
        response_dict = password_valid
    if not password_valid:
        response_dict['error'] = 'invalid password'

    return response_dict

@app.route('/new_user', methods=['POST'])
def new_user():
    """Store new user credentials in DynamoDB."""
    username = request.form.get('username')
    password = request.form.get('password')

    try:
        ddb_fetch_user_data(username)
        return {
            'success': False,
            'error': 'user already exists'
        }
    except ValueError:
        # User not found, which is good
        pass

    response = nitro_create_user_credentials(password)
    print(response)
    if not response['success']:
        return response

    ddb_store_user_data(
        username,
        response['data']['password_hash_b64'],
        response['data']['encrypted_pepper_b64']
    )
    return {
        'success': True
    }

def ddb_fetch_user_data(username):
    """Fetch user data from DynamoDB."""
    users_table = dynamodb.Table(DYNAMODB_TABLE)
    response = users_table.get_item(
            Key={
                'username' : username,
            }
        )

    if 'Item' in response:
        return response['Item']

    raise ValueError('User not found in database')

def ddb_store_user_data(username, password_hash, encrypted_pepper):
    """Store user credentials in DynamoDB."""
    users_table = dynamodb.Table(DYNAMODB_TABLE)
    users_table.put_item(
        Item={
            'username': username,
            'password_hash': password_hash,
            'encrypted_pepper': encrypted_pepper
        }
    )

def nitro_create_user_credentials(password):
    """Connect to Nitro Enclave to create new credentials."""
    return communicate_with_enclave({
        'action': 'generate_hash_and_pepper',
        'kms_region': REGION,
        'kms_key': KMS_ALIAS,
        'kms_credentials': fetch_aws_credentials(),
        'password': password
    })

def nitro_verify_user_credentials(password, password_hash, encrypted_pepper):
    """Connect to Nitro Enclave and verify password."""
    return communicate_with_enclave({
        'action': 'validate_credentials',
        'kms_region': REGION,
        'kms_key': KMS_ALIAS,
        'kms_credentials': fetch_aws_credentials(),
        'password': password,
        'password_hash': password_hash,
        'encrypted_pepper': encrypted_pepper
    })

def communicate_with_enclave(dictionary):
    """Send a message to the Enclave and read the response."""
    try:
        vsock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) # pylint:disable=no-member
        vsock.connect((ENCLAVE_CID, ENCLAVE_PORT))
        vsock.send(str.encode(json.dumps(dictionary)))
        return_data = vsock.recv(1024).decode()
        return json.loads(return_data)
    except Exception as exc: # pylint:disable=broad-except
        return {
            'success': False,
            'error': str(exc)
        }

def fetch_aws_credentials():
    """Fetch the AWS session token from the metadata service."""
    instance_profile_response = requests.get(
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    )
    instance_profile_name = instance_profile_response.text

    sec_credentials_response = requests.get(
        f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{instance_profile_name}'
    )
    response = sec_credentials_response.json()

    return {
        'aws_access_key_id' : response['AccessKeyId'],
        'aws_secret_access_key' : response['SecretAccessKey'],
        'aws_session_token' : response['Token']
    }
