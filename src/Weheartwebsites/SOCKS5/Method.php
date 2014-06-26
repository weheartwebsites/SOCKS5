<?php

/**
 * This file is part of the php-epp2 library.
 *
 * (c) Gunter Grodotzki <gunter@weheartwebsites>
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Weheartwebsites\SOCKS5;

/**
 * @link http://www.iana.org/assignments/socks-methods/socks-methods.xhtml
 */
interface Method
{
    public function getId();

    public function run(Client $client);
}