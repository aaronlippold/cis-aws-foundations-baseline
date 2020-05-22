# encoding: UTF-8

control "4.4" do
  title "Ensure routing tables for VPC peering are \"least access\""
  desc  "Once a VPC peering connection is estalished, routing tables must be updated to establish any connections between the peered VPCs. These routes can be as specific as desired - even peering a VPC to only a single host on the other side of the connection."
  desc  "rationale", "Being highly selective in peering routing tables is a very effective way of minimizing the impact of breach as resources outside of these routes are inaccessible to the peered VPC."
  desc  "check", "Review routing tables of peered VPCs for whether they route all subnets of each VPC and whether that is necessary to accomplish the intended purposes for peering the VPCs.

    Via CLI:

    1. List all the route tables from a VPC and check if \"GatewayId\" is pointing to a _

    \t_ (e.g. pcx-1a2b3c4d) and if \"DestinationCidrBlock\" is as specific as desired.
    ```
    aws ec2 describe-route-tables --filter \"Name=vpc-id,Values=\" --query \"RouteTables[*].{RouteTableId:RouteTableId, VpcId:VpcId, Routes:Routes, AssociatedSubnets:Associations[*].SubnetId}\"
    ```"
  desc  "fix", "Remove and add route table entries to ensure that the least number of subnets or hosts as is required to accomplish the purpose for peering are routable.

    Via CLI:

    1. For each __ containing routes non compliant with your routing policy (which grants more than desired \"least access\"), delete the non compliant route:
    ```
    aws ec2 delete-route --route-table-id  --destination-cidr-block
    ```
     2. Create a new compliant route:
    ```
    aws ec2 create-route --route-table-id  --destination-cidr-block --vpc-peering-connection-id

    ```"
  impact 0.5
  tag severity: "Medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: nil
  tag notes: nil
  tag comment: nil
  tag cis_controls: "TITLE:Protect Information through Access Control Lists CONTROL:14.6 DESCRIPTION:Protect all information stored on systems with file system, network share, claims, application, or database specific access control lists. These controls will enforce the principle that only authorized individuals should have access to the information based on their need to access the information as a part of their responsibilities.;"
  tag ref: "http://docs.aws.amazon.com/AmazonVPC/latest/PeeringGuide/peering-configurations-partial-access.html"

  
end

