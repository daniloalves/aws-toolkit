import boto3.session

region_name = 'us-west-2'
profile_name = 'm_prod'

def get_session(region_name=region_name,profile_name=profile_name):
    session = boto3.session.Session(region_name=region_name, profile_name=profile_name)
    return session