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

Output:

<img src="https://i.imgur.com/YJgFlSg.png"/>

User: ‘glitch’ is not recognised so we investigate.
**jq -r '["Event_Time", "Event_Source", "Event_Name", "User_Name", "Source_IP"],(.Records[] | select(.userIdentity.userName == "glitch") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
**

Output:

<img src="https://i.imgur.com/oLHjYk1.png"/>

Identify user-agent (even though attacker can change this when attacking) by adding it to the code 
**jq -r '["Event_Time", "Event_type", "Event_Name", "User_Name", "Source_IP", "User_Agent"],(.Records[] | select(.userIdentity.userName == "glitch") | [.eventTime,.eventType, .eventName, .userIdentity.userName //"N/A",.sourceIPAddress //"N/A", .userAgent //"N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'**

<img src="https://i.imgur.com/K9fBqeL.png"/>

The anomalous account uses a **Google Chrome browser** within a **Mac OS system.**
This is the userAgent string for the internal console used in AWS. It doesn’t provide much information.
The next interesting event to look for is who created this anomalous user account. We will filter for all **IAM-related events**, and this can be done by using the select filter 
**jq -r '["Event_Time", "Event_Source", "Event_Name", "User_Name", "Source_IP"], (.Records[] | select(.eventSource == "iam.amazonaws.com") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'**

**iam.amazonaws.com** is identity access management for AWS and how users are created and managed.

<img src="https://i.imgur.com/jg0lXwu.png"/>


The user mcskidy invoked the CreateUser action and consequently invoking the **AttachUserPolicy** (privilege escalation) action. The source IP where the requests were made is **53.94.201.69**. Remember that it is the same IP the anomalous user glitch used.

Output the records with the following eventsource and eventname:
**jq '.Records[] |select(.eventSource=="iam.amazonaws.com" and .eventName== "CreateUser")' cloudtrail_log.json
**

<img src="https://i.imgur.com/FWBpjjx.png"/>

User mcskidy created the account so we now filter for the eventname **AttachUserPolicy** to uncover the permissions set for the newly created user. This event applies access policies to users, defining the extent of access to the account.

<img src="https://i.imgur.com/6c43JZ2.png"/>

In **“policyARN”** we can see administrator access was granted to the user. McSkidy is baffled by these results. She knows that she did not create the anomalous user and did not assign the privileged access. She also doesn’t recognise the IP address involved in the events and does not use a Mac OS; she only uses a Windows machine. All this information is different to the typical IP address and machine used by McSkidy, so she wants to prove her innocence and asks to continue the investigation.

The results from the following code: 
jq -r '["Event_Time", "Event_Source", "Event_Name", "User_Name", "Source_IP"], (.Records[] | select(.sourceIPAddress=="53.94.201.69") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A", .sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'.

Display all events tagged from the chosen IP address which escalated permissions.

Based on the command output, three user accounts (mcskidy, glitch, and mayor_malware) were accessed from the same IP address. The next step is to check each user and see if they always work from that IP.
jq -r '["Event_Time","Event_Source","Event_Name", "User_Name","User_Agent","Source_IP"],(.Records[] | select(.userIdentity.userName=="PLACEHOLDER") | [.eventTime, .eventSource, .eventName, .userIdentity.userName // "N/A",.userAgent // "N/A",.sourceIPAddress // "N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'.

Replace **‘PLACEHOLDER’** with user we want to look at (mcskidy, glitch, and mayor_malware).

This will tell us the IP, browser and **OS** they use and the similarities and differences in the user’s behaviours.

The bank logs can be found in **file ~/wareville_logs/rds.log.**

**grep INSERT rds.log **will show all of the bank logs.
