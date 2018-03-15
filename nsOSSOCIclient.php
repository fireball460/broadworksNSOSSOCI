<?php

$msgId = 0;

$versionMajor = 1;
$versionMinor = 0;
$msgType = 0;
$msgReplyExpected = 0;
$msgStatus = 0;
$msgErrorCode = 0;
$protocol= 5;  //16 for NSOCI
$nextKeepAliveDelay = 0;
$RepliesTo = -1;

$bodyLen = 0;
$OCIbody = "";

// set up NS OSS/OCI user credential
$bwuserid = "";
$bwuserPasswd = "";
$bwServerIP = "";
$bwServerPort = 2220;


function ReplyMessageUnpack($data)
{
  $bitReceived = (string)unpack('H*',$data)[1];
  $recevedData['protocolPrefix'] = substr($bitReceived, 0, 8);
  $recevedData['versionMajor'] = substr($bitReceived, 8, 4);
  $recevedData['versionMinor'] = substr($bitReceived, 12, 4);
  $recevedData['msgId'] = hexdec(substr($bitReceived, 16, 16));

  $recevedData['msgType'] = substr($bitReceived, 32, 2);
  $recevedData['msgReplyExpected'] = substr($bitReceived, 34, 2);
  $recevedData['msgStatus'] = substr($bitReceived, 36, 2);
  $recevedData['msgErrorCode'] = substr($bitReceived, 38, 2);

  $recevedData['protocol'] = hexdec(substr($bitReceived, 40, 4));
  $recevedData['nextKeepAliveDelay'] = substr($bitReceived, 44, 4);

  $recevedData['RepliesTo'] = hexdec(substr($bitReceived, 48, 16));
  $recevedData['bodyLen'] = hexdec(substr($bitReceived, 64, 8));
  $recevedData['body'] = substr($bitReceived, 72, strlen($bitReceived));

var_dump($recevedData);

  return $recevedData;

}


$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
$result = socket_connect($sock, $bwServerIP, $bwServerPort);

// Protocol registration

$dataWithHeader = 'BCCT'.pack('nnJccccnnJN',$versionMajor, $versionMinor, $msgId, $msgType, $msgReplyExpected, $msgStatus, $msgErrorCode, $protocol, $nextKeepAliveDelay, $RepliesTo, $bodyLen);
var_dump(unpack('H*',$dataWithHeader));
$socketWrite = socket_write($sock, $dataWithHeader );
$reponse = null;
    $out = socket_read($sock,36); 
         var_dump($out);
       $receiveResponseArray = ReplyMessageUnpack($out);


// Login Request

$msgId = $receiveResponseArray['msgId']+1;

  $OCIbody = '<?xml version = "1.0" encoding = "ISO-8859-1"?>';
  $OCIbody .='<com.broadsoft.protocols.nsoss.BroadsoftDocument protocol = "NSOSS" version = "20.0">';
  $OCIbody .='<command commandType = "requestAuthentication">';
  $OCIbody .='<commandData>';
  $OCIbody .='<loginInfo>';
  $OCIbody .='<loginId>'.$bwuserid.'</loginId>';
  $OCIbody .='</loginInfo>';
  $OCIbody .='</commandData>';
  $OCIbody .='</command>';
  $OCIbody .='</com.broadsoft.protocols.nsoss.BroadsoftDocument>';

$msgType = 2;
$msgReplyExpected = 1;
$bodyLen = strlen($OCIbody);

$dataWithHeader = 'BCCT'.pack('nnJccccnnJN',$versionMajor, $versionMinor, $msgId, $msgType, $msgReplyExpected, $msgStatus, $msgErrorCode, $protocol, $nextKeepAliveDelay, $RepliesTo, $bodyLen). $OCIbody;
$socketWrite = socket_write($sock, $dataWithHeader );
// $out = socket_read($sock,4);
$response = null;
     $response = socket_read($sock,36); 
     
$receiveResponseArray = ReplyMessageUnpack($response);
//$out = socket_read($sock,32);
$receiveResponseArray['body'] = socket_read($sock,$receiveResponseArray['bodyLen']);
 var_dump($receiveResponseArray['body']);







// send Password
$msgId = $receiveResponseArray['msgId']+1;

$responseXML = new SimpleXMLElement($receiveResponseArray['body']);
var_dump($responseXML);
$nonce = $responseXML->command->commandData->loginInfo->nonce;
$S1 = sha1($bwuserPasswd);
        $S2 = $nonce.":".$S1;
        $enc_pass = md5($S2);
 $OCIbody = '<?xml version="1.0" encoding="UTF-8"?>';
 $OCIbody .= '<com.broadsoft.protocols.nsoss.BroadsoftDocument protocol="NSOSS" version="20.0">';
 $OCIbody .= '<command commandType="requestLogin">';
 $OCIbody .= '<commandData>';
 $OCIbody .= '<loginInfo>';
 $OCIbody .= '<loginId>'.$bwuserid.'</loginId>';
 $OCIbody .= '<password>'.$enc_pass.'</password>';
 $OCIbody .= '</loginInfo>';
 $OCIbody .= '</commandData>';
 $OCIbody .= '</command>';
 $OCIbody .= '</com.broadsoft.protocols.nsoss.BroadsoftDocument>';

$msgType = 2;
$msgReplyExpected = 1;
$bodyLen = strlen($OCIbody);

$dataWithHeader = 'BCCT'.pack('nnJccccnnJN',$versionMajor, $versionMinor, $msgId, $msgType, $msgReplyExpected, $msgStatus, $msgErrorCode, $protocol, $nextKeepAliveDelay, $RepliesTo, $bodyLen). $OCIbody;

$socketWrite = socket_write($sock, $dataWithHeader );
// $out = socket_read($sock,4);
$response = null;
     $response = socket_read($sock,36);
     
$receiveResponseArray = ReplyMessageUnpack($response);
//$out = socket_read($sock,4);
$receiveResponseArray['body'] = socket_read($sock,$receiveResponseArray['bodyLen']);
 var_dump($receiveResponseArray['body']);


// OCI protocol registration
$msgId = $receiveResponseArray['msgId']+1;
$protocol = 16;
$msgType = 0;
$msgReplyExpected = 0;
$bodyLen = 0;
$dataWithHeader = 'BCCT'.pack('nnJccccnnJN',$versionMajor, $versionMinor, $msgId, $msgType, $msgReplyExpected, $msgStatus, $msgErrorCode, $protocol, $nextKeepAliveDelay, $RepliesTo, $bodyLen);
var_dump(unpack('H*',$dataWithHeader));
$socketWrite = socket_write($sock, $dataWithHeader );
$reponse = null;
    $out = socket_read($sock,36);
         var_dump($out);
       $receiveResponseArray = ReplyMessageUnpack($out);



// Send OCI request

echo "Sending OCI msg";

$protocol = 16;
$msgId = $receiveResponseArray['msgId']+1;

$OCIbody = '<?xml version="1.0" encoding="ISO-8859-1"?>';
$OCIbody .= '<BroadsoftDocument protocol="NSOCI" xmlns="C" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">';
$OCIbody .= '<sessionId xmlns="">'.$bwuserid.'</sessionId>';
$OCIbody .= '<command xsi:type="RoutingPolicyNumberPortabilityGetOutNumberListRequest" xmlns="">';
$OCIbody .= '<name>DefaultInst</name>';
$OCIbody .= '</command>';
$OCIbody .= '</BroadsoftDocument>';

$msgType = 2;
$msgReplyExpected = 1;
$bodyLen = strlen($OCIbody);

$dataWithHeader = 'BCCT'.pack('nnJccccnnJN',$versionMajor, $versionMinor, $msgId, $msgType, $msgReplyExpected, $msgStatus, $msgErrorCode, $protocol, $nextKeepAliveDelay, $RepliesTo, $bodyLen). $OCIbody;

var_dump(unpack('H*',$dataWithHeader));


$socketWrite = socket_write($sock, $dataWithHeader );

$response = null;
     $response = socket_read($sock,36);

$receiveResponseArray = ReplyMessageUnpack($response);
//$out = socket_read($sock,4);
$receiveResponseArray['body'] = socket_read($sock,$receiveResponseArray['bodyLen']);
 var_dump($receiveResponseArray['body']);



// OSS Log out

echo "Log out Request";

$protocol = 5;
$msgId = $receiveResponseArray['msgId']+1;

  $OCIbody = '<?xml version = "1.0" encoding = "ISO-8859-1"?>';
  $OCIbody .='<com.broadsoft.protocols.nsoss.BroadsoftDocument protocol = "NSOSS" version = "20.0">';
  $OCIbody .='<command commandType = "requestLogout">';
  $OCIbody .='<commandData>';
  $OCIbody .='<loginInfo>';
  $OCIbody .='<loginId>'.$bwuserid.'</loginId>';
  $OCIbody .='<reason>Logout requested by user</reason>';
  $OCIbody .='</loginInfo>';
  $OCIbody .='</commandData>';
  $OCIbody .='</command>';
  $OCIbody .='</com.broadsoft.protocols.nsoss.BroadsoftDocument>';

$msgType = 2;
$msgReplyExpected = 1;
$bodyLen = strlen($OCIbody);

$dataWithHeader = 'BCCT'.pack('nnJccccnnJN',$versionMajor, $versionMinor, $msgId, $msgType, $msgReplyExpected, $msgStatus, $msgErrorCode, $protocol, $nextKeepAliveDelay, $RepliesTo, $bodyLen). $OCIbody;
$socketWrite = socket_write($sock, $dataWithHeader );
// $out = socket_read($sock,4);
$response = null;
     $response = socket_read($sock,36);

$receiveResponseArray = ReplyMessageUnpack($response);
//$out = socket_read($sock,32);
$receiveResponseArray['body'] = socket_read($sock,$receiveResponseArray['bodyLen']);
 var_dump($receiveResponseArray['body']);



// protocol unregister
$msgId = $msgId+ 1;

$msgType = 5;
$msgReplyExpected = 0;
$RepliesTo = -1;

$bodyLen = 0;

$dataWithHeader = 'BCCT'.pack('nnJccccnnJN',$versionMajor, $versionMinor, $msgId, $msgType, $msgReplyExpected, $msgStatus, $msgErrorCode, $protocol, $nextKeepAliveDelay, $RepliesTo, $bodyLen);
var_dump(unpack('H*',$dataWithHeader));
$socketWrite = socket_write($sock, $dataWithHeader );
$reponse = null;


// socket close
socket_close($sock);





?>