<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use ArrayObject;
use DateTime;

/**
 * A security assertion. Encapsulates the identity and authorization of a user who has been
 * authenticated by some trusted system.
 */
class Assertion extends \ArrayObject
{
    /**
     * @param array $data
     */
    public function __construct($data = [])
    {
        parent::__construct($data, ArrayObject::ARRAY_AS_PROPS);
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return 'user_'.$this->userId;
    }

    /**
     * Get an identifier for the user who has been authenticated.
     *
     * @return string
     */
    public function getUserId()
    {
        return isset($this->userId) ? $this->userId : null;
    }

    /**
     * @param string $userId
     * @return Assertion
     */
    public function setUserId($userId)
    {
        $this->userId = $userId;
        return $this;
    }

    /**
     * Get an identifier for the system that issued this assertion.
     *
     * @return string
     */
    public function getIssuer()
    {
        return isset($this->issuer) ? $this->issuer : null;
    }

    /**
     * @param string $issuer
     * @return Assertion
     */
    public function setIssuer($issuer)
    {
        $this->issuer = $issuer;
        return $this;
    }

    /**
     * Get a list of the systems that this assertion was intended for.
     *
     * @return string[] Each value is an audience identifier, usually a client ID or a URI.
     */
    public function getAudience()
    {
        return isset($this->audience) ? $this->audience : null;
    }

    /**
     * @param string[] $audience
     * @return Assertion
     */
    public function setAudience(array $audience)
    {
        $this->audience = $audience;
        return $this;
    }

    /**
     * @param string $audience
     * @return bool
     */
    public function hasAudience($audience)
    {
        if (!isset($this->audience) || !is_array($this->audience))
            return false;
        return in_array($audience, $this->audience);
    }

    /**
     * Get any scope identifiers associated with the assertion. These may limit the purposes for
     * which the assertion should be trusted.
     *
     * @return string[]
     */
    public function getScopes()
    {
        return isset($this->scopes) ? $this->scopes : null;
    }

    /**
     * @param string[] $scopes
     * @return Assertion
     */
    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;
        return $this;
    }

    /**
     * @param string $scope
     * @return bool
     */
    public function hasScope($scope)
    {
        if (!isset($this->scopes) || !is_array($this->scopes))
            return false;
        return in_array($scope, $this->scopes);
    }

    /**
     * Get the date after which the assertion should no longer be trusted.
     *
     * @return DateTime|null
     */
    public function getExpiryDate()
    {
        return isset($this->expiryDate) ? $this->expiryDate : null;
    }

    /**
     * @param DateTime $expiryDate
     * @return Assertion
     */
    public function setExpiryDate($expiryDate)
    {
        $this->expiryDate = $expiryDate;
        return $this;
    }

    /**
     * Get an identifier for the user who requested this assertion, if different from the value
     * of getUserId().
     *
     * @return string
     */
    public function getRealUserId()
    {
        return isset($this->realUserId) ? $this->realUserId : null;
    }

    /**
     * @param string $realUserId
     * @return Assertion
     */
    public function setRealUserId($realUserId)
    {
        $this->realUserId = $realUserId;
        return $this;
    }
}