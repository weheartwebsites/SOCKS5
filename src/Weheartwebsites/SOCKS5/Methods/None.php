<?php

/**
 * This file is part of the SOCKS5 library.
 *
 * (c) Gunter Grodotzki <guenter@weheartwebsites.de>
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Weheartwebsites\SOCKS5\Methods;

use Weheartwebsites\SOCKS5\Method;
use Weheartwebsites\SOCKS5\Client;

/**
 * This authentication does not require anything nor does it do anything
 */
class None implements Method
{
    const ID = 0x00;

    public function getId()
    {
        return self::ID;
    }

    public function authenticate(Client $client)
    {
        // do nothing
        return true;
    }
}