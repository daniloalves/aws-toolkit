#!/bin/bash

profile="prod"
region="us-west-2"

aws_command="aws --profile $profile --region $region"

check_status(){
	id="$1"

	status="$($aws_command ec2 describe-instance-status --instance-id $id --query 'InstanceStatuses[0].SystemStatus.Status')"
	echo $status # null/ok
}
modify_instance(){
	id="$1"
	instance_type="$2"

	result="$($aws_command ec2 modify-instance-attribute --instance-id $id --instance-type \"{\"Value\": \"$instance_type\"})"
	echo $result
}

main(){
	if [ "$#" -lt 2 ];then
		echo -e "What's the instance ID?\n"
		read id
		echo -e "What's the instance Type?\n"
		read instance_type
	fi
	echo "Executing shutdown.."
	stop_instance $id
	sleep 10
	while [ true ];
	do
		if [ "$(check_status $id)" == "null" ];then
			echo "Executing changing.."
			modify=$(modify_instance $id $instance_type)
			if [ "$modify" != "" ];then
				echo "Some error happened."
				echo "$modify"
				exit 1
			else
				break;
			fi
		fi
		echo "Waiting finish shutdown.."
		sleep 3
	done
	echo "Starting Instance.."
	start_instance $id
	sleep 10
	check_status $id

}

main $*
