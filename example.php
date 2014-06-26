<?php

// debug
error_reporting(E_ALL);
ini_set('display_errors', true);

require 'src/Weheartwebsites/autoload.php';

use Weheartwebsites\SOCKS5\Client as SOCKS5Client;
use Weheartwebsites\SOCKS5\Methods\None as AuthNone;

$socks_client = new SOCKS5Client('127.0.0.1');
$socks_client->addMethod(new AuthNone);
//$socks_client->setTunnelDNS(true);

$request = [
    'GET / HTTP/1.1',
    'Host: curlmyip.com',
    'Connection: close',
];

try {

    $socks_client->connect();

    $socks_client->connectTo('curlmyip.com', 80);

    var_dump(fwrite($socks_client->socket, implode("\r\n", $request) . "\r\n\r\n"));

    $head = $body = $buffer = null;
    $is_header = true;

    // I know this is shitty, but just for a quick demonstration....
    while (true) {
        $buffer = fgets($socks_client->socket);
        if ($buffer === false) {
            usleep(200000);
            continue;
        }

        if ($is_header) {
            $head .= $buffer;

            if (substr($head, -4) == "\r\n\r\n") {
                $is_header = false;
                // get rest bytes
                $head = rtrim(str_replace("\r\n", "\n", $head));
                if (!preg_match('/^content\-length:\s*(\d+)$/im', $head, $matches)) {
                    echo "error";
                    break;
                }
                $rest = (int) $matches[1];
            }
        } else {
            $body .= $buffer;
            $rest -= strlen($buffer);

            if ($rest <= 0) {
                $body = rtrim($body);
                break;
            }
        }
    }

    var_dump($head);
    var_dump($body);

    unset($socks_client);

} catch (Exception $e) {
    unset($socks_client);
    echo $e->getMessage() . PHP_EOL;
    exit(1);
}
