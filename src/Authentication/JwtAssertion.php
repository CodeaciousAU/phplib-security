<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use DateTime;
use InvalidArgumentException;

/**
 * A security assertion that was extracted from a JSON Web Token.
 */
class JwtAssertion extends Assertion
{
    /**
     * @var array
     */
    private $claims;


    /**
     * Construct an assertion from a set of authenticated JWT claims.
     *
     * At minimum, the subject claim ('sub') is required, because it identifies the authenticated
     * user.
     *
     * If OpenID Connect claims are present, the assertion may provide additional details
     * about the authenticated user, such as name and email address.
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1
     * @see http://openid.net/specs/openid-connect-core-1_0.html#Claims
     *
     * @param array $claims
     */
    public function __construct(array $claims)
    {
        parent::__construct($claims);

        if (empty($claims['sub']))
            throw new InvalidArgumentException('Missing required claim "sub"');

        $this->claims = $claims;
        $this->setUserId($claims['sub']);

        if (is_array($claims['aud']))
            $this->setAudience($claims['aud']);
        else
            $this->setAudience([$claims['aud']]);

        if (!empty($claims['iss']))
            $this->setIssuer($claims['iss']);

        if (isset($claims['exp']) && is_numeric($claims['exp']))
            $this->setExpiryDate(new DateTime('@'.$claims['exp']));

        if (isset($claims['scope']))
            $this->setScopes(explode(' ', $claims['scope']));

        if (isset($claims['real_user']))
            $this->setRealUserId($claims['real_user']);
    }

    /**
     * @param string $name
     * @return bool
     */
    public function hasClaim($name)
    {
        return isset($this->claims[$name]);
    }

    /**
     * @param string $name
     * @param mixed $default
     * @return mixed
     */
    public function getClaim($name, $default=null)
    {
        if (!$this->hasClaim($name))
            return $default;
        return $this->claims[$name];
    }

    /**
     * @return array
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * @return string|null
     */
    public function getDisplayName()
    {
        return $this->getClaim('name');
    }

    /**
     * @return string|null
     */
    public function getFirstName()
    {
        return $this->getClaim('given_name');
    }

    /**
     * @return string|null
     */
    public function getSurname()
    {
        return $this->getClaim('family_name');
    }

    /**
     * @return string|null
     */
    public function getEmailAddress()
    {
        return $this->getClaim('email');
    }
}