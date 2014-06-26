<?php

/**
 * This file is part of the SOCKS5 library.
 *
 * (c) Gunter Grodotzki <guenter@weheartwebsites>
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Weheartwebsites\SOCKS5\Methods;

use Weheartwebsites\SOCKS5\Method;
use Weheartwebsites\SOCKS5\Client;
use Exception;

/**
 * Plaintext Username/Password authentication
 * @link http://tools.ietf.org/html/rfc1929
 */
class Plain implements Method
{
    const ID             = 0x02;

    const VER            = 0x01;
    const STATUS_SUCCESS = 0x00;

    protected $username;

    protected $password;

    /**
     * @param string $username
     * @param string $password
     */
    public function __construct($username, $password)
    {
        $this->username = (string) $username;
        $this->password = (string) $password;
    }

    public function getId()
    {
        return self::ID;
    }

    public function authenticate(Client $client)
    {
        $login_string  = pack('CC', self::VER, mb_strlen($this->username, 'ASCII'));
        $login_string .= $this->username;
        $login_string .= pack('C', mb_strlen($this->password, 'ASCII'));
        $login_string .= $this->password;

        $client->send($login_string);

        $response = unpack('Cver/Cstatus', $client->recv());

        if (!isset($response['ver'], $response['status'])) {
            throw new Exception('PlainAuth: unable to parse response');
        }

        if ($response['ver'] !== self::VER) {
            throw new Exception(sprintf('PlainAuth: version mismatch (server: %d / client: %d)', $response['ver'], self::VER));
        }

        if ($response['status'] !== self::STATUS_SUCCESS) {
            throw new Exception('PlainAuth: unsuccessful login');
        }

        return true;
    }
}