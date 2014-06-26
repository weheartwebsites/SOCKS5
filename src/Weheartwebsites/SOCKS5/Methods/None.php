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

class None implements Method
{
    const ID = 0x00;

    public function getId()
    {
        return self::ID;
    }

    public function run(Client $client)
    {
        // do nothing
        return true;
    }
}