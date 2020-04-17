<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security;

use Codeacious\Security\Authentication\JwtAssertion;
use Codeacious\Security\Authentication\JwtSignerFactory;
use Codeacious\Security\Exception\ConfigurationException;
use Codeacious\Security\Exception\RuntimeException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;

/**
 * Generates and verifies cryptographically-signed JSON Web Tokens, which can be used for web
 * authentication and other purposes.
 */
class WebTokenManager
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Signer\Key
     */
    private $signingKey;

    /**
     * @var Signer\Key
     */
    private $verificationKey;

    /**
     * @var string
     */
    private $issuer = '';

    /**
     * @var int
     */
    private $lifetime = 3600;


    /**
     * @param array|\ArrayAccess $config
     *
     * @throws ConfigurationException
     * @throws RuntimeException
     */
    public function __construct($config)
    {
        if (!is_array($config) && ! ($config instanceof \ArrayAccess))
            throw new RuntimeException('The constructor expects an array or array-like object');

        if (empty($config['algorithm']))
            throw new ConfigurationException('Missing required config key "algorithm"');

        $this->signer = JwtSignerFactory::signerForAlgorithm($config['algorithm']);
        if ($this->signer instanceof Signer\Rsa || $this->signer instanceof Signer\Ecdsa)
        {
            if (empty($config['private_key']))
                throw new ConfigurationException('Missing required config key "private_key"');
            if (($privateKey = file_get_contents($config['private_key'])) === false)
                throw new RuntimeException('Unable to read key file '.$config['private_key']);
            $this->signingKey = new Signer\Key($privateKey);

            if (empty($config['public_key']))
                throw new ConfigurationException('Missing required config key "public_key"');
            if (($publicKey = file_get_contents($config['public_key'])) === false)
                throw new RuntimeException('Unable to read key file '.$config['public_key']);
            $this->verificationKey = new Signer\Key($publicKey);
        }
        else
        {
            if (empty($config['key']))
                throw new ConfigurationException('Missing required config key "key"');
            if (($key = file_get_contents($config['key'])) === false)
                throw new RuntimeException('Unable to read key file '.$config['key']);

            $this->signingKey = new Signer\Key($key);
            $this->verificationKey = $this->signingKey;
        }

        if (!empty($config['issuer']))
            $this->setIssuer($config['issuer']);
        if (!empty($config['lifetime']))
            $this->setLifetime($config['lifetime']);
    }

    /**
     * @return string
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * Set the token issuer. This should be in the form of a URL.
     *
     * @param string $issuer
     * @return WebTokenManager
     */
    public function setIssuer($issuer)
    {
        $this->issuer = $issuer;
        return $this;
    }

    /**
     * @return int Seconds
     */
    public function getLifetime()
    {
        return $this->lifetime;
    }

    /**
     * Set the token lifetime. This will determine how long until a token expires.
     *
     * @param int $lifetime Seconds
     * @return WebTokenManager
     */
    public function setLifetime($lifetime)
    {
        $this->lifetime = $lifetime;
        return $this;
    }

    /**
     * Create a new general-purpose token with an arbitrary claims set.
     *
     * @param array $claims Associative array
     * @return string The JWT token encoded as a string
     */
    public function createToken(array $claims)
    {
        $builder = new Builder();

        foreach ($claims as $name => $value)
            $builder->withClaim($name, $value);

        if (!isset($claims['iat']))
            $builder->issuedAt(time());

        if (!isset($claims['exp']))
            $builder->expiresAt(time()+$this->lifetime);

        return (string)$builder->getToken($this->signer, $this->signingKey);
    }

    /**
     * Generate an OAuth 2.0-compliant JWT bearer token for authentication purposes.
     *
     * @param string|array $audience Usually this is a client ID or URI (an identifier of the system
     *    that will consume the token)
     * @param string $subject Usually this is a user ID (an identifier of the account this token
     *    grants access to)
     * @param string|array $scope Optional scope string(s)
     * @param string $realUser Applicable only when a user is impersonating another user for this
     *    session. Pass the user ID of the user doing the impersonation.
     * @param array $extraClaims Optional associative array
     *
     * @return string The JWT token encoded as a string
     */
    public function createBearerToken($audience, $subject, $scope='', $realUser=null,
                                      $extraClaims=[])
    {
        $builder = new Builder();
        $builder->permittedFor($audience)
            ->relatedTo($subject)
            ->identifiedBy($this->_makeID())
            ->withClaim('token_type', 'bearer');

        if (!empty($this->issuer))
            $builder->issuedBy($this->issuer);

        if (!empty($realUser))
            $builder->withClaim('real_user', $realUser);

        if (!empty($scope))
        {
            if (is_array($scope))
                $scope = implode(' ', $scope);
            $builder->withClaim('scope', $scope);
        }

        foreach ($extraClaims as $name => $value)
            $builder->withClaim($name, $value);

        if (!isset($extraClaims['iat']))
            $builder->issuedAt(time());

        if (!isset($extraClaims['exp']))
            $builder->expiresAt(time()+$this->lifetime);

        return (string)$builder->getToken($this->signer, $this->signingKey);
    }

    /**
     * Authenticate a general-purpose token and return the claim set.
     *
     * In the resulting array, the keys are strings and the values are JSON-compatible types.
     *
     * @param string $token
     * @return array|null The set of claims that the token contained, or null if the token is
     *    invalid or expired.
     */
    public function authenticateToken($token)
    {
        //Parse token
        try
        {
            $jwt = (new Parser())->parse($token);
        }
        catch (\Exception $e)
        {
            return null;
        }

        //Check signature
        if (!$jwt->verify($this->signer, $this->verificationKey))
            return null;

        //Check exp, iat, nbf (if present)
        if (!$jwt->validate(new ValidationData()))
            return null;

        return array_map(fn (Claim $claim) => $claim->getValue(), $jwt->getClaims());
    }

    /**
     * Authenticate an OAuth 2.0-compliant JWT bearer token.
     *
     * @param string $token
     * @return JwtAssertion|null The authentication assertion embodied by the token, or null if the
     *    token is invalid or expired
     */
    public function authenticateBearerToken($token)
    {
        $values = $this->authenticateToken($token);
        if ($values === null)
            return null;

        if (empty($values['token_type']) || $values['token_type'] != 'bearer')
            return null;

        if (!empty($this->issuer))
        {
            if (empty($values['iss']) || $values['iss'] != $this->issuer)
                return null;
        }

        if (empty($values['sub']) || empty($values['aud']))
            return null;

        return new JwtAssertion($values);
    }

    /**
     * @return string
     */
    protected function _makeID()
    {
        return bin2hex(random_bytes(20));
    }
}