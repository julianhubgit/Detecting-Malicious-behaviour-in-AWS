# Detecting-Malicious-behaviour-in-AWS

<h2>Description</h2>

Providing a detailed walkthrough on analyzing **AWS CloudWatch** logs to discover malicious behavior with **JQ**.


<h2>Languages and Utilities Used</h2>

- AWS CloudWatch
- AWS CloudTrail
- JQ

<h2>Some information about AWS CloudWatch, CloudTrail  and JQ</h2>

**EC2s** are virtualized instances in **AWS cloud**. Logs within **AWS CloudWatch** can be analysed. **AWS CloudWatch** is a monitoring platform that tracks system and application metrics, configures alarms, and centralizes logs from various cloud services. It requires installing a CloudWatch agent on instances to capture and store these logs effectively.

- **Log Events**: Individual, timestamped log entries with messages and metadata.
- **Log Streams**: Collections of log events from a single source.
- **Log Groups**: Collections of related log streams

**AWS CloudTrail** tracks user, role, and service actions in an AWS environment by recording events in **JSON format**. It offers a 90-day queryable event history, allows custom trails for specific monitoring needs, and can deliver logs to **CloudWatch** for centralized access. An **AWS S3 bucket** is like **“FTP in cloud”**. **JQ** in command line parses **JSON data.**

<h2>Task and in depth breakdown</h2>

If “book title” was an element we knew was in the **.json** file, this is how we would access it: **JQ** takes two inputs: the filter you want to use, followed by the input file. We start our **JQ** filter with a . which just tells **JQ** we are accessing the current input. From here, we want to access the array of values stored in our **JSON (with the []).** Making our filter a .[]. For example, let’s run the following command: **jq  '.[] | .book_title' book_list.json.**

This will print all the book titles in the **book_list.json **file.

Below is a breakdown of the scenario being used to carry out the task:

<img src="https://i.imgur.com/Jdi3dU5.png" alt="Scenario"/>

A typical S3 log:

<img src="https://i.imgur.com/PTRVHG1.png" alt="S3 Bucket"/>

Below is a breakdown of what we may find in an AWS CloudTrail log:

- userIdentity:	Details of the user account that acted on an object.
- eventTime:	When did the action occur?
- eventType:	What type of event occurred? (e.g., AwsApiCall or AwsConsoleSignIn, AwsServiceEvent)
- eventSource:	From what service was the event logged?
- eventName:	What specific action occurred? (e.g., ListObjects, GetBucketObject)
- sourceIPAddress:	From what IP did the action happen?
- userAgent:	What user agent was used to perform the action? (e.g., Firefox, AWS CLI)
- requestParameters:	What parameters were involved in the action? (e.g., BucketName)

We use this command to search through the CloudTrail logs:
**jq -r '.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares")' cloudtrail_log.json
**

<img src="https://i.imgur.com/TbBBN1J.png"/>

An updated code to only display the parameters we are looking for is:
**jq -r '.Records[] | select(.eventSource == "s3.amazonaws.com" and .requestParameters.bucketName=="wareville-care4wares") | [.eventTime, .eventName, .userIdentity.userName // "N/A",.requestParameters.bucketName // "N/A", .requestParameters.key // "N/A", .sourceIPAddress // "N/A"]' cloudtrail_log.json**

<img src="https://i.imgur.com/GjM71xb.png"/>



