# aws-toolkit

Tools and Scripts useful to future.

## First Set up
1. export PYTHONPATH=$PYTHONPATH:./aws-toolkit
1. virtualenv -p python3 venv
1. pip install -r requirements.txt
1. source venv/bin/activate

## Next usages
1. export PYTHONPATH=$PYTHONPATH:./aws-toolkit
1. source venv/bin/activate

# EC2

## Change Type Script
* Getting help message:
`python ec2/change_type.py`

* Change Instance Type
`python ec2/change_type.py --instance_ids i-a1b2c3 --instance_type r4.large`

