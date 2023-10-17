import argparse as argparse
import boto3 as boto3
import datetime as datetime
import emoji as emoji
import platform as platform
import time as time
import subprocess as subprocess  # nosec - B404:import_subprocess
import sys as sys
import logging as logging
from botocore.exceptions import ClientError
from shutil import get_terminal_size as get_terminal_size
from shutil import which as which


# Retrieve a list of the function ARNs for the specified Region
def retrieve_function_arns(lambda_client, region):
    function_arns = []
    retrieve_function_arns.count = 0
    functions = lambda_client.list_functions()
    for fn in functions['Functions']:
        retrieve_function_arns.count += 1
        function_arns.append(str(fn['FunctionArn']))
    print(emoji.emojize(":information:  Found {} functions in the AWS ",
                        language='alias').format(
        retrieve_function_arns.count) + region + " region\n")
    if (retrieve_function_arns.count == 0):
        print(emoji.emojize(":heavy_exclamation_mark:  The script will now exit!",
                            language='alias'))
        sys.exit()
    # print("Now running the following Athena queries:\n")
    # print("1) Create the Athena table for CloudTrail")
    # print("2) Add a partition for 'year' to the new table")
    # print("3) Query Athena for the Lambda functions that have been invoked in the past 30 days\n")
    # time.sleep(2)
    return function_arns


def run_query(athena_client, query, region, athena_s3_bucket_name):
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': 'default'},
        ResultConfiguration={
            'OutputLocation': f"{athena_s3_bucket_name}-{region}"
        },
    )
    print('Query Execution ID: ' + response['QueryExecutionId'])
    execution_status = None
    while execution_status != 'SUCCEEDED':
        waiter = athena_client.get_query_execution(
            QueryExecutionId=response['QueryExecutionId'].lstrip('ID')
        )
        execution_status = waiter['QueryExecution']['Status']['State']

        if execution_status == 'FAILED':
            print("The query failed. Check the Athena history for details.")
            return

        print("Running")
        time.sleep(5)

    return athena_client.get_query_results(
        QueryExecutionId=response['QueryExecutionId']
    )


def build_query_strings(function_arns, table_name, cloudtrail_s3_bucket_name, year, region):
    print('-' * get_terminal_size()[0])
    # Convert the list of function ARNs to a comma-separated string
    function_arns_csv = str(function_arns)[1:-1]

    create_table_query_template = \
        """CREATE EXTERNAL TABLE {0} (
            eventversion STRING,
            userIdentity STRUCT<
            type:STRING,
            principalid:STRING,
            arn:STRING,
            accountid:STRING,
            invokedby:STRING,
            accesskeyid:STRING,
            userName:STRING,
            sessioncontext:STRUCT<
                attributes:STRUCT<
                mfaauthenticated:STRING,
                creationdate:STRING>,
                sessionIssuer:STRUCT<
                type:STRING,
                principalId:STRING,
                arn:STRING,
                accountId:STRING,
                userName:STRING>>>,
            eventTime STRING,
            eventSource STRING,
            eventName STRING,
            awsRegion STRING,
            sourceIpAddress STRING,
            userAgent STRING,
            errorCode STRING,
            errorMessage STRING,
            requestParameters STRING,
            responseElements STRING,
            additionalEventData STRING,
            requestId STRING,
            eventId STRING,
            resources ARRAY<STRUCT<
            ARN:STRING,accountId:
            STRING,type:STRING>>,
            eventType STRING,
            apiVersion STRING,
            readOnly STRING,
            recipientAccountId STRING,
            serviceEventDetails STRING,
            sharedEventID STRING,
            vpcEndpointId STRING
            )
            PARTITIONED BY(year string)
            ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
            STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
            OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
            LOCATION '{1}';"""

    # Query to add a partition for the year to the CloudTrail table in Athena
    create_partiton_query_template = """
    ALTER TABLE {0} add partition (year="{3}")
    location '{1}/CloudTrail/{2}/{3}/'"""

    # Query used to search for Lambda data event Invoke activities for the past 30 days
    last_run_query_template = """
    select json_extract_scalar(requestparameters, '$.functionName') as function_name, Max (eventtime) as "Last Run"
    from {0}
    where eventname='Invoke'
    and year='{1}'
    and from_iso8601_timestamp(eventtime) > current_timestamp - interval '1' month
    and json_extract_scalar(requestparameters, '$.functionName') in ({function_arns})
    group by json_extract_scalar(requestparameters, '$.functionName')"""

    create_table_query = create_table_query_template.format(
        table_name,
        cloudtrail_s3_bucket_name)
    # print(create_table_query)
    # print()

    create_partition_query = create_partiton_query_template.format(
        table_name,
        cloudtrail_s3_bucket_name,
        region,
        year)
    # print(create_partition_query)
    # print()

    last_run_query = last_run_query_template.format(
        table_name,
        year,
        function_arns=function_arns_csv)
    # print(last_run_query)
    # print('-' * get_terminal_size()[0])

    return create_table_query, create_partition_query, last_run_query


def get_set_of_function_arns_from_result_set(result_set):
    set_of_functions_used = set()
    get_set_of_function_arns_from_result_set.count = 0
    for row in result_set[1:]:
        get_set_of_function_arns_from_result_set.count += 1
        function_arn = row['Data'][0]['VarCharValue']
        set_of_functions_used.add(function_arn)
    return set_of_functions_used


def main():
    # Set up logging
    logger = logging.getLogger(__name__)

   # Configure logging.
    logging.basicConfig(level=logging.ERROR,
                        format='%(levelname)s: %(message)s')

    # Add arguments to the parser.
    parser = argparse.ArgumentParser(exit_on_error=False)

    # AWS region that you want to evaluate
    # The script will only work in regions where Athena is supported
    # Athena region availability can be found at https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/
    parser.add_argument('-r', '--region',
                        help='The AWS region you wish to execute the script in. Default is us-east-1',
                        default='us-east-1',
                        required=True,
                        choices=(
                            'af-south-1',
                            'ap-east-1',
                            'ap-northeast-1',
                            'ap-northeast-2',
                            'ap-south-1',
                            'ap-south-2',
                            'ap-southeast-1',
                            'ap-southeast-2',
                            'ap-southeast-3',
                            'ap-southeast-4',
                            'ca-central-1',
                            'cn-north-1',
                            'cn-northwest-1',
                            'eu-central-1',
                            'eu-central-2',
                            'eu-north-1',
                            'eu-south-1',
                            'eu-west-1',
                            'eu-west-2',
                            'eu-west-3',
                            'me-south-1',
                            'me-central-1',
                            'sa-east-1',
                            'us-east-1',
                            'us-east-2',
                            'us-gov-east-1',
                            'us-gov-west-1',
                            'us-west-1',
                            'us-west-2'
                        )
                        )
    # The AWS profile to use
    parser.add_argument('-p', '--profile',
                        help='The AWS profile to use. Default is default',
                        default='default',
                        required=False
                        )

    # The Athena S3 bucket name
    parser.add_argument('-a', '--athena_s3_bucket_name',
                        help='The S3 bucket name for Athena to use as a staging area in the format s3://bucket-name',
                        required=True
                        )

    # The cloudtrail lambda logs table name
    parser.add_argument('-t', '--table_name',
                        help='The name of the Athena table to create',
                        default='cloudtrail_lambda_logs',
                        required=False
                        )

    # The CloudTrail S3 bucket name
    parser.add_argument('-c', '--cloudtrail_s3_bucket_name',
                        help='The S3 bucket name for CloudTrail logs in the format s3://bucket-name',
                        required=True
                        )

    # The year to query
    parser.add_argument('-y', '--year',
                        help='The year to query. Defaults to the current year',
                        default=datetime.datetime.now().year,
                        )

    # Parse the arguments.
    args = parser.parse_args()

    # Print lines to separate the output from the previous command.
    print('-' * get_terminal_size()[0])

    # Display the computer platform that this script is running on.
    print(emoji.emojize(":computer:  Platform: {}",
          language='alias').format(platform.platform()))

    # Display the version of Python that this script is running with
    print(emoji.emojize(":snake:  Python version: {}",
          language='alias').format(sys.version))

    # Check that the Python version is 3 or higher.
    if sys.version_info[0] < 3:
        print(emoji.emojize(
            'You must use Python 3 or higher :cross_mark:',
            language='alias'))
        # Print an error message and raise an exception.
        raise ValueError("You must use Python 3 or higher")
    else:
        print(emoji.emojize(
            ':check_mark_button:  Python version is OK,',
            language='alias'))

    # Check that the AWS CLI is installed.
    if which('aws') is None:
        print(emoji.emojize(
            ':cross_mark:  AWS CLI is not installed!',
            language='alias'))
        # Print an error message and raise an exception.
        raise ValueError("AWS CLI is not installed")
    else:
        print(emoji.emojize(
            ':check_mark_button:  AWS CLI is installed.',
            language='alias'))
        # Get the version of the AWS CLI.
        aws_cli_version = subprocess.check_output(
            ['aws', '--version']).decode('utf-8').split(' ')[0]  # nosec B603 B607
        # Check that the AWS CLI version is less than verson 2.
        if int(aws_cli_version.split('/')[1].split('.')[0]) < 2:
            # Print an error message and raise an exception.
            print(emoji.emojize(
                ':heavy_exclamation_mark:  You must use AWS CLI version 2 or higher!',
                language='alias'))
            raise ValueError("You must use AWS CLI version 2 or higher")
        else:
            # Display the version of the AWS CLI.
            print(emoji.emojize(":ok:  AWS CLI version: {}", language='alias').format(
                aws_cli_version.split('/')[1]))

    # Display the version of the Boto3 library.
    print(emoji.emojize(":package:  Boto3 version: {}",
          language='alias').format(boto3.__version__))
    # Display the version of the Emoji library.
    print(emoji.emojize(":package:  Emoji version: {}",
          language='alias').format(emoji.__version__))
    # Display the version of the Argparse library.
    print(emoji.emojize(":package:  Argparse version: {}",
          language='alias').format(argparse.__version__))
    # Display the version of the Logging library.
    print(emoji.emojize(":package:  Logging version: {}",
          language='alias').format(logging.__version__))
    # Display the version of the Platform library.
    print(emoji.emojize(":package:  Platform version: {}",
          language='alias').format(platform.__version__))

    # Display the values of the command-line arguments.
    #
    # Display the region.
    print(emoji.emojize(":gear:  Region: {}",
          language='alias').format(args.region))
    # Display the AWS profile.
    print(emoji.emojize(":gear:  AWS profile: {}", language='alias').format(
        args.profile))
    # Display the Athena S3 bucket name.
    print(emoji.emojize(":gear:  Athena S3 bucket name: {}", language='alias').format(
        args.athena_s3_bucket_name))
    # Display the Athena table name.
    print(emoji.emojize(":gear:  Athena table name: {}", language='alias').format(
        args.table_name))
    # Display the CloudTrail S3 bucket name.
    print(emoji.emojize(":gear:  CloudTrail S3 bucket name: {}", language='alias').format(
        args.cloudtrail_s3_bucket_name))
    # Display the year.
    print(emoji.emojize(":gear:  Year: {}", language='alias').format(args.year))

    # create clients for Lambda and Athena
    lambda_client = boto3.client('lambda',
                                 region_name=args.region)
    athena_client = boto3.client('athena',
                                 region_name=args.region)

    # Retrieve a list of the function ARNs for the specified Region
    function_arns = retrieve_function_arns(
        lambda_client=lambda_client, region=args.region)

    # Build the queries
    queries = build_query_strings(function_arns=function_arns,
                                  year=args.year,
                                  table_name=args.table_name,
                                  cloudtrail_s3_bucket_name=args.cloudtrail_s3_bucket_name,
                                  region=args.region)
    print("Starting queries")
    query_results = [
        run_query(
            athena_client=athena_client,
            query=q,
            athena_s3_bucket_name=args.athena_s3_bucket_name,
            region=args.region,
        )
        for q in queries
    ]
    print("Completed queries")
    # We made sure that the last query run gets the data that we care about
    result_set = query_results[-1]['ResultSet']['Rows']
    print("Retrieved results")
    # Get the set of functions that have not been invoked in the past 30 days
    set_of_functions_used = get_set_of_function_arns_from_result_set(
        result_set)
    # Print the set of functions that have been invoked in the past 30 days
    print(set_of_functions_used)

    # Compare the results from Athena to the list of existing functions and print the difference
    unusedcount = retrieve_function_arns.count - \
        get_set_of_function_arns_from_result_set.count

    # Print the number of functions that haven't been invoked in the past 30 days
    print(
        f"\nOut of the {retrieve_function_arns.count}, there are {unusedcount} functions that haven't been invoked in the past 30 days"
    )

    # create a list of the functions that haven't been invoked in the past 30 days
    difference_list = list(set(function_arns) - set_of_functions_used)
    # Sort the list of functions that haven't been invoked in the past 30 days
    difference_list.sort(key=str.lower)

    # Print the list of functions that haven't been invoked in the past 30 days
    for stale_function_arn in difference_list:
        print(stale_function_arn)

    # Let the user know that the script is done.
    print(emoji.emojize(":checkered_flag:  Done!", language='alias'))
    print('-' * get_terminal_size()[0])
    return


# The main function.
if __name__ == "__main__":
    main()

# End of script
