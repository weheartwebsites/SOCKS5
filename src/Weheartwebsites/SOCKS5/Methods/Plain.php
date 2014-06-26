<?php

/**
 * This file is part of the php-epp2 library.
 *
 * (c) Gunter Grodotzki <gunter@weheartwebsites>
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Weheartwebsites\SOCKS5\Methods;

use Weheartwebsites\SOCKS5\Method;
use Weheartwebsites\SOCKS5\Client;

class Plain implements Method
{
    const ID = 0x02;

    protected $username;

    protected $password;

    public function __construct($username, $password)
    {
        $this->username = (string) $username;
        $this->password = (string) $password;
    }

    public function getId()
    {
        return self::ID;
    }

    public function run(Client $client)
    {
        $login_string  = '';
        $login_string .= pack('CC', 0x01, mb_strlen($this->username, 'ASCII'));
        $login_string .= $this->username;
        $login_string .= pack('C', mb_strlen($this->password, 'ASCII'));
        $login_string .= $this->password;

        if ($client->send($login_string) !== true) {
            return false;
        }

        $response = unpack('Cversion/Cstatus', $client->recv());

        if (!isset($response['status']) || $response['status'] !== 0x00) {
            return false;
        }

        return true;
    }
}