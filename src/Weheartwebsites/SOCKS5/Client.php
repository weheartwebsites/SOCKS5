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

use Exception;

/**
 * a SOCKS5 connection wrapper
 * @link http://tools.ietf.org/html/rfc1928
 */
class Client
{
    const SOCKS_VERSION = 0x05;

    public $socket;

    protected $proxy_server;

    protected $proxy_port;

    protected $methods = [];

    protected $outgoing_interface;

    protected $timeout;

    protected $connect_timeout;

    protected $tunnel_dns;

    public function __construct($proxy_server, $proxy_port = 1080)
    {
        $this->proxy_server = (string) $proxy_server;
        $this->proxy_port   = (int) $proxy_port;

        // set defaults
        $this->connect_timeout = $this->timeout = ini_get('default_socket_timeout');
    }

    public function __destruct()
    {
        $this->close();
    }

    public function addMethod(Method $method)
    {
        $this->methods[$method->getId()] = $method;
    }

    /**
     * sets IP to be used for outgoing connections (e.g. bindto)
     * @param string $ip (dotted)
     * @throws Exception
     */
    public function setOutgoingInterface($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4|FILTER_FLAG_NO_RES_RANGE)) {
            throw new Exception(sprintf('%s is not a valid IPv4 address', $ip));
        }

        $this->outgoing_interface = $ip;
    }

    /**
     * sets IO timeout
     * @param int $timeout
     */
    public function setTimeout($timeout)
    {
        $this->timeout = (int) $timeout;
    }

    /**
     * sets connect timeout
     * @param int $connect_timeout
     */
    public function setConnectTimeout($connect_timeout)
    {
        $this->connect_timeout = (int) $connect_timeout;
    }

    /**
     * set to true to have all dns requests go via the SOCKS proxy, otherwise
     * DNS queries will be done local/directly
     * @param bool $tunnel_dns
     */
    public function setTunnelDNS($tunnel_dns)
    {
        $this->tunnel_dns = (bool) $tunnel_dns;
    }

    /**
     * connect to the SOCKS proxy server
     */
    public function connect()
    {
        $context = $this->createContext();

        $target = sprintf('tcp://%s:%d', $this->proxy_server, $this->proxy_port);

        if (is_resource($context)) {
            $this->socket = @stream_socket_client($target, $errno, $errstr, $this->connect_timeout, STREAM_CLIENT_CONNECT, $context);
        } else {
            $this->socket = @stream_socket_client($target, $errno, $errstr, $this->connect_timeout, STREAM_CLIENT_CONNECT);
        }

        if ($this->socket === false) {
            throw new Exception(sprintf('connect(): (%d) %s', $errno, $errstr));
        }

        // set stream time out
        if (!stream_set_timeout($this->socket, $this->timeout)) {
            throw new Exception('connect(): unable to set stream timeout');
        }

        // set to non-blocking
        if (!stream_set_blocking($this->socket, 0)) {
            throw new Exception('connect(): unable to set non-blocking');
        }

        return $this->negotiate();
    }

    /**
     * closes connection to the SOCKS proxy server
     * @return boolean
     */
    public function close()
    {
        if (is_resource($this->socket)) {
            return fclose($this->socket);
        }

        return;
    }

    /**
     * connect to destination server via the established SOCKS connection
     * @param string $host
     * @param int $port
     */
    public function connectTo($host, $port)
    {
        if (!is_resource($this->socket)) {
            throw new Exception('connectTO(): dead socket');
        }

        $host = (string) $host;
        $port = (int) $port;

        if ($this->tunnel_dns) {
            $connect_string = pack('C5', self::SOCKS_VERSION, 0x01, 0x00, 0x03, mb_strlen($host, 'ASCII')) . $host . pack('n', $port);
        } else {
            // resolve host
            $host_addr = gethostbyname($host);
            if ($host_addr === false || $host_addr === $host) {
                throw new Exception(sprintf('connectTo(): unable to resolve %s', $host));
            }
            $connect_string = pack('C4Nn', self::SOCKS_VERSION, 0x01, 0x00, 0x01, ip2long($host_addr), $port);
        }

        if ($this->send($connect_string) !== true) {
            return false;
        }

        // currently will only work with IPv4 replies, ipv6 is trivial but domain-name is not...
        $buffer = $this->recv(10);

        $response = unpack('Cversion/Cresult/Creg/Ctype/Lip/Sport', $buffer);

        if (!isset($response['version'], $response['result']) || $response['version'] !== self::SOCKS_VERSION || $response['result'] !== 0x00) {
            throw new Exception(sprintf('connectTo(): connection failed (%s:%d)', $host, $port));
        }

        return true;
    }

    /**
     * fwrite wrapper
     * @param string $string
     * @throws Exception
     * @return int written bytes
     */
    public function send($string)
    {
        if (!is_resource($this->socket)) {
            throw new Exception('send(): dead socket');
        }

        $info = stream_get_meta_data($this->socket);
        $hard_time_limit = time() + $this->timeout + 2;
        $length = mb_strlen($string, 'ASCII');

        $pos = 0;
        while (!$info['timed_out'] && !feof($this->socket)) {

            $wlen = $length - $pos;

            // currently set chunk length to 4KB, should be configurable in future
            if ($wlen > 4096) {
                $wlen = 4096;
            }

            // try write remaining data from socket
            $written = @fwrite($this->socket, mb_substr($string, $pos, $wlen, 'ASCII'), $wlen);

            // If we read something, bump up the position
            if ($written) {
                $pos += $written;

                // break if all written
                if ($pos === $length) {
                    break;
                }
            } else {
                // sleep 0.2s
                usleep(200000);
            }

            // update metadata
            $info = stream_get_meta_data($this->socket);
            if (time() >= $hard_time_limit) {
                throw new Exception('send(): hard-timeout while writing');
            }
        }

        // check for timeout
        if ($info['timed_out']) {
            throw new Exception('send(): soft-timeout while writing');
        }

        if ($pos !== $length) {
            throw new Exception('send(): writing short %d bytes', $length - $pos);
        } else {
            return true;
        }
    }

    public function recv($length)
    {
        if (!is_resource($this->socket)) {
            throw new Exception('recv(): dead socket');
        }

        $result = '';

        $info = stream_get_meta_data($this->socket);
        $hard_time_limit = time() + $this->timeout + 2;

        while (!$info['timed_out'] && !feof($this->socket)) {

            // Try read remaining data from socket
            $buffer = @fread($this->socket, $length - mb_strlen($result, 'ASCII'));

            // If the buffer actually contains something then add it to the result
            if ($buffer !== false) {

                $result .= $buffer;

                // break if all data received
                if (mb_strlen($result, 'ASCII') === $length) {
                    break;
                }
            } else {
                // sleep 0.25s
                usleep(200000);
            }

            // update metadata
            $info = stream_get_meta_data($this->socket);
            if (time() >= $hard_time_limit) {
                throw new Exception('recv(): hard-timeout while reading');
            }
        }

        // check for timeout
        if ($info['timed_out']) {
            throw new Exception('recv(): soft-timeout while reading');
        }

        return $result;
    }

    /**
     * optionally creates a stream context depending on the config
     */
    private function createContext()
    {
        if ($this->outgoing_interface === null) {
            return;
        }

        $context = stream_context_create();

        if (!stream_context_set_option($context, 'socket', 'bindto', sprintf('%s:%d', $this->outgoing_interface, 0))) {
            throw new Exception(sprintf('there was an error binding to: %s', $this->outgoing_interface));
        }

        return $context;
    }

    /**
     * negotiate server version and auth method
     */
    private function negotiate()
    {
        if (!is_resource($this->socket)) {
            throw new Exception('negotiate(): dead socket');
        }

        // get available client-side methods
        if (empty($this->methods) || !is_array($this->methods)) {
            throw new Exception('negiotiate(): at least one method must be given');
        }

        $neg_string  = pack('C', self::SOCKS_VERSION); // version
        $neg_string .= pack('C', count($this->methods)); // number of methods
        foreach ($this->methods as $method) {
            $neg_string .= pack('C', $method->getId());
        }

        if ($this->send($neg_string) !== true) {
            return false;
        }

        // https://bugzilla.mindrot.org/show_bug.cgi?id=2250

        $response = unpack('Cversion/Cmethod', $this->recv(2));

        if (!isset($response['version'], $response['method'])) {
            throw new Exception('negotiate(): unable to get response');
        }

        if ($response['version'] !== self::SOCKS_VERSION) {
            throw new Exception(sprintf('negotiate(): server version (%d) unsupported', $response['version']));
        }

        if ($response['method'] === 0xFF) {
            throw new Exception('negotiate(): server does not accept client method');
        }

        if (!isset($this->methods[$response['method']])) {
            throw new Exception('negotiate(): server method not available to client');
        }

        // run login
        return $this->methods[$response['method']]->run($this);
    }
}