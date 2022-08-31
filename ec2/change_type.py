from time import sleep
from utils.session import get_session
from utils.logger import logger_aws_toolkit
import argparse

logger_toolkit = logger_aws_toolkit()
session = get_session()
ec2 = session.client('ec2')

DEFAULT_SLEEP_TIME = 1*60

def ec2_stop_instances(instance_ids=[]):
    logger_toolkit.debug(f"Stopping: {instance_ids}")
    response = ec2.stop_instances(
        InstanceIds=instance_ids,
        DryRun=False
    )
    logger_toolkit.debug(response)
    return response

def ec2_instances_state(instance_ids=[]):
    logger_toolkit.debug(f"Getting state: {instance_ids}")
    instances_state = []

    response = ec2.describe_instance_status(
        InstanceIds=instance_ids,
    )
    logger_toolkit.debug(response)
    for instance in response['InstanceStatuses']:
        instance_state = instance['InstanceState']['Name']
        instance_id = instance['InstanceId']
        instances_state.append({'instance_id':instance_id,'instance_state':instance_state})
    return instances_state

def ec2_start_instances(instance_ids=[]):
    logger_toolkit.debug(f"Starting: {instance_ids}")
    response = ec2.start_instances(
        InstanceIds=instance_ids,
        DryRun=False
    )
    logger_toolkit.debug(response)
    return response

def ec2_change_type(instance_ids=[], instance_type=None):
    logger_toolkit.debug(f"Changing: {instance_ids}")
    stop_instances = ec2_stop_instances(instance_ids)
    sleep(DEFAULT_SLEEP_TIME)
    
    check_instances_state = ec2_instances_state(instance_ids)
    while True:
        all_good = True
        for instance_state in check_instances_state:
            id = instance_state['instance_state']
            stopped = instance_state['instance_state']
            if stopped != 'stopped':
                all_good = False
                logger_toolkit.info(f"[{id}] Wating stop.")
        if all_good:
            break;
        else:
            check_instances_state = ec2_instances_state(instance_ids)
    
    def self_ec2_change_type():
        logger_toolkit.debug(f"self changing: {instance_ids}")
        for instance_id in instance_ids:
            response = ec2.modify_instance_attribute(
                InstanceId=instance_id,
                InstanceType={
                    'Value': instance_type,
                },
            )
            logger_toolkit.debug(response)

    self_ec2_change_type()
    ec2_start_instances(instance_ids)

    return {}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--instance_ids', type=str, nargs="+", required=True)
    parser.add_argument('-t', '--instance_type', type=str, required=True)

    args = parser.parse_args()

    logger_toolkit.info(f"Starting EC2 Instance Changing:")
    logger_toolkit.info(f"instance_ids: {args.instance_ids}")
    logger_toolkit.info(f"instance_type: {args.instance_type}")
    ec2_change_type(args.instance_ids, args.instance_type)

    


