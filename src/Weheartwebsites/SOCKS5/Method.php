<?php

/**
 * This file is part of the SOCKS5 library.
 *
 * (c) Gunter Grodotzki <guenter@weheartwebsites.de>
 *
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace Weheartwebsites\SOCKS5;

/**
 * describes how a auth method has to work
 */
interface Method
{
    /**
     * Returns the ID of the implemented method. See link for a list of valid IDs
     * @link http://www.iana.org/assignments/socks-methods/socks-methods.xhtml
     */
    public function getId();

    /**
     * Do the actual authentication
     * @param Client $client
     */
    public function authenticate(Client $client);
}