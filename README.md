command line version.

```
$ python cloudTrailReduce.py -h
Usage: -b <bucket>, -d <yyyy-mm-dd>, -r <region>

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -b BUCKET, --bucket=BUCKET
                        bucket containing cloudtrail logs.
  -d DATE, --date=DATE  date to process. format yyyy-mm-dd.
  -r REGION, --region=REGION
                        region. ex: us-east-1.
```

# cloudTrailReduce
parses AWS cloudTrail logs into a reduced form that can be used to easily produce least-privileged IAM policies
