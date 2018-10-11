#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

jq --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Please Install 'jq' https://stedolan.github.io/jq/ to execute this script"
	echo
	exit 1
fi
starttime=$(date +%s)

echo "POST request Enroll on Org1  ..."
echo
############################### NOTE ###############################
# If testing with new user, please user http://localhost:3000/users
#   otherwise, keep it as http://localhost:3000/token
####################################################################
ORG1_TOKEN=$(curl -s -X POST \
  http://localhost:3000/token \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=TestUser&orgName=org1')
echo $ORG1_TOKEN
ORG1_TOKEN=$(echo $ORG1_TOKEN | jq ".token" | sed "s/\"//g")
echo
echo "ORG1 token is $ORG1_TOKEN"
echo
echo "POST invoke chaincode on peers of Org1"
echo
TRX_ID=$(curl -s -X POST \
  http://localhost:3000/channels/defaultchannel/chaincodes/mycc \
  -H "authorization: Bearer $ORG1_TOKEN" \
  -H "content-type: application/json" \
  -d '{
	"peers": ["org1-peer1"],
	"fcn":"write",
	"args":["test_key","test_value"]
}')
echo "Transaction ID is $TRX_ID"
echo
echo

echo "GET read chaincode on peer1 of Org1"
echo
curl -s -X GET \
  "http://localhost:3000/channels/defaultchannel/chaincodes/mycc?fcn=read&args=%5B%22test_key%22%5D" \
  -H "authorization: Bearer $ORG1_TOKEN" \
  -H "content-type: application/json"
echo
echo
TRX_ID=$(echo $TRX_ID | jq ".txid" | sed "s/\"//g")

#echo "POST Adding a test factor"
#echo
#TRX_ID=$(curl -s -X POST \
#  http://localhost:3000/channels/defaultchannel/chaincodes/mycc \
#  -H "authorization: Bearer $ORG1_TOKEN" \
#  -H "content-type: application/json" \
#  -d '{
#	"fcn":"storeFactor",
#	"args":["{\"address\" : \"1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX\", \"email\" : \"lbathen@gmail.com\", \"type\" : \"facial\", \"payload\" : [\"1/1011000100000001\", \"2/1011000100000001\", \"3/1011000100000001\"]}"]
#}')
#echo "Transacton ID is $TRX_ID"
#echo
#echo

#echo "GET query a factor on peer1 of Org1"
#echo
#curl -s -X GET \
#  "http://localhost:3000/channels/defaultchannel/chaincodes/mycc?peer=peer1&fcn=getFactor&args=%5B%221F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX%22%5D" \
#  -H "authorization: Bearer $ORG1_TOKEN" \
#  -H "content-type: application/json"
#echo
#echo

#exit 0

echo "GET query Block by blockNumber"
echo
curl -s -X GET \
  "http://localhost:3000/channels/defaultchannel/blocks/1" \
  -H "authorization: Bearer $ORG1_TOKEN" \
  -H "content-type: application/json"
echo
echo

echo "GET query Transaction by TransactionID"
echo
curl -s -X GET http://localhost:3000/channels/defaultchannel/transactions/$TRX_ID \
  -H "authorization: Bearer $ORG1_TOKEN" \
  -H "content-type: application/json"
echo
echo


############################################################################
### TODO: What to pass to fetch the Block information
############################################################################
#echo "GET query Block by Hash"
#echo
#hash=????
#curl -s -X GET \
#  "http://localhost:3000/channels/defaultchannel/blocks?hash=$hash&peer=peer1" \
#  -H "authorization: Bearer $ORG1_TOKEN" \
#  -H "cache-control: no-cache" \
#  -H "content-type: application/json" \
#  -H "x-access-token: $ORG1_TOKEN"
#echo
#echo


echo "POST request Token for Admin on Org1  ..."
echo
ORG1_TOKEN=$(curl -s -X POST \
  http://localhost:3000/token \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=admin&orgName=org1')
echo $ORG1_TOKEN
ORG1_TOKEN=$(echo $ORG1_TOKEN | jq ".token" | sed "s/\"//g")
echo
echo "ORG1 token is $ORG1_TOKEN"
echo
echo "POST invoke chaincode on peers of Org1"
echo

echo "GET query ChainInfo"
echo
curl -s -X GET \
  "http://localhost:3000/channels/defaultchannel" \
  -H "authorization: Bearer $ORG1_TOKEN" \
  -H "content-type: application/json"
echo
echo

echo "GET query Installed chaincodes"
echo
curl -s -X GET \
  "http://localhost:3000/chaincodes" \
  -H "authorization: Bearer $ORG1_TOKEN" \
  -H "content-type: application/json"
echo
echo

echo "GET query Instantiated chaincodes"
echo
curl -s -X GET \
  "http://localhost:3000/channels/mycc/chaincodes" \
  -H "authorization: Bearer $ORG1_TOKEN" \
  -H "content-type: application/json"
echo
echo

echo "GET query Channels"
echo
curl -s -X GET \
  "http://localhost:3000/channels" \
  -H "authorization: Bearer $ORG1_TOKEN" \
  -H "content-type: application/json"
echo
echo


echo "Total execution time : $(($(date +%s)-starttime)) secs ..."
