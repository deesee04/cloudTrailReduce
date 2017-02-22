#!/usr/bin/env python
from __future__ import print_function

## imports.

import json
import boto3
import os, sys
import gzip
import botocore
from optparse import OptionParser

## main aws resources.

s3resource = boto3.resource('s3')
s3client = boto3.client('s3')

## custom print function.

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def oprint(*args, **kwargs):
    print(*args, file=sys.stdout, **kwargs)

## download the gzipped cloudtrail archive.

def get_trail_gzip(bucket, key):
    try:
        object = s3resource.Object(bucket, key).download_file('/tmp/in.gzip')
    except:
        raise Exception('Exception ocurred retrieving CloudTrail object S3::%s/%s' % (bucket,key))
 
## extract the contents from the downloaded archive.

def extract_trail_gzip():
    try:
        with gzip.open('/tmp/in.gzip', 'rb') as infile:
            with open('/tmp/out.json', 'w') as outfile:
                for line in infile:
                    outfile.write(line)
    except:
        raise Exception('Exception ocurred when extacting /tmp/in.gzip /tmp/out.json')
 
## load in the records.

def load_trail_records():
    with open('/tmp/out.json') as data_file:
        try:
            trail_json = json.load(data_file)
            records = trail_json['Records']
        except:
            raise Exception('Exception ocurred when parsing /tmp/out.json to JSON object')
    return records

## process each record. 
## output a fully formed iam policy json string.

def munge_record(record):
    try:
        event_name = record['eventName'].encode('utf-8')
        event_source = record['eventSource'].encode('utf-8')
        split_source = event_source.split(".")
        service = split_source[0]
        try:
            arn = record['userIdentity']['arn']
            policy_string = {}
            policy_string = service + ":" + event_name
            return_object = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow', 
                    'Principal': { 
                        'AWS' : [
                            arn
                        ]
                    }, 
                    'Action': [
                        policy_string
                    ]
                }]
            }
            try:
                resources = record['resources']
                return_object['Statement'][0]['Resource'] = []
                for resource in resources:
                    return_object['Statement'][0]['Resource'].append(resource['ARN'])
            except:
                pass
            return return_object
        except:
            pass
    except:
        raise Exception('Exception ocurred when munging record: %s' % (record))

## parse the policy template.
## if the template is empty, it's our first record, so just append it.
## if the template is NOT empty, check the existing template for the IAM ID and associated resources, appending only new values.

def parse_policy_template(policy_template, record):
    if (record != None):
        match = False
        if not policy_template:
            policy_template.append(record)
        else:
            for existing_record in policy_template:
                if (existing_record['Statement'][0]['Principal']['AWS'][0] in record['Statement'][0]['Principal']['AWS']):
                    match = True
                    if (record['Statement'][0]['Action'][0] in existing_record['Statement'][0]['Action']):
                        pass
                    else:
                        existing_record['Statement'][0]['Action'].append(record['Statement'][0]['Action'][0])
                        existing_record['Statement'][0]['Action'] = sorted(existing_record['Statement'][0]['Action'])
                    try:
                        if (record['Statement'][0]['Resource'][0] in existing_record['Statement'][0]['Resource']):
                            pass
                        else:
                            existing_record['Statement'][0]['Resource'].append(record['Statement'][0]['Resource'][0])
                            existing_record['Statement'][0]['Resource'] = sorted(existing_record['Statement'][0]['Resource'])
                    except:
                        pass
            if not match:
                policy_template.append(record)
    return policy_template

## print the final template.

def post_policy_template(policy_template):
    #with open('/tmp/iamOut.json', 'w') as f:
    oprint(json.dumps(policy_template, indent=4))

## run the application logic.

def run(bucket, date, region):
    account_num = boto3.client('sts').get_caller_identity().get('Account')
    date_split = date.split('-')
    policy_template = []
    bucket_resource = s3resource.Bucket(bucket)
    bucket_prefix = "AWSLogs/" + account_num + "/CloudTrail/" + region + "/" + date_split[0] + "/" + date_split[1] + "/" + date_split[2]
    all_matching_objects = bucket_resource.objects.filter(Prefix=bucket_prefix)
    total_objects = sum(1 for _ in bucket_resource.objects.filter(Prefix=bucket_prefix))
    i = 0

    for matched_object in all_matching_objects:
        get_trail_gzip(bucket, matched_object.key)
        extract_trail_gzip()
        trail_records = load_trail_records()
        for record in trail_records:
            record = munge_record (record)
            policy_template = parse_policy_template(policy_template, record)
        i = i + 1
        completed_string = "completed [" + str(i) + "/" + str(total_objects) + "]"
        eprint(completed_string, matched_object.key)
 
    post_policy_template(policy_template)

## init options.
## call the main application logic. 

if __name__ == "__main__":

    parser = OptionParser(usage="-b <bucket>, -d <yyyy-mm-dd>, -r <region>", version="0.1")
    parser.add_option("-b", "--bucket", action="store", help="bucket containing cloudtrail logs.")
    parser.add_option("-d", "--date", action="store", help="date to process. format yyyy-mm-dd.")
    parser.add_option("-r", "--region", action="store", help="region. ex: us-east-1.")

    (options, args) = parser.parse_args()
    if ((options.bucket == None) or (options.date == None) or (options.region == None)):
        print ( "missing arguments. try -h." )
        sys.exit()
    else:
        run(options.bucket, options.date, options.region)