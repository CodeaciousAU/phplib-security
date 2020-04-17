<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use Codeacious\Security\Exception\ConfigurationException;
use Lcobucci\JWT\Signer;

class JwtSignerFactory
{
    public static function signerForAlgorithm(string $algorithm): Signer
    {
        switch ($algorithm)
        {
            case 'ES256': return new Signer\Ecdsa\Sha256();
            case 'ES384': return new Signer\Ecdsa\Sha384();
            case 'ES512': return new Signer\Ecdsa\Sha512();
            case 'HS256': return new Signer\Hmac\Sha256();
            case 'HS384': return new Signer\Hmac\Sha384();
            case 'HS512': return new Signer\Hmac\Sha512();
            case 'RS256': return new Signer\Rsa\Sha256();
            case 'RS384': return new Signer\Rsa\Sha384();
            case 'RS512': return new Signer\Rsa\Sha512();
            default:
                throw new ConfigurationException('Unsupported algorithm: '.$algorithm);
        }
    }
}