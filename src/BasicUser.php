<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security;

use Codeacious\Acl\Acl;
use Codeacious\Acl\Principal\Principal;

/**
 * A minimal model representing an authenticated user.
 */
class BasicUser implements User
{
    /**
     * @var mixed
     */
    private $id;

    /**
     * @var string
     */
    private $displayName;

    /**
     * @var string|null
     */
    private $firstName;

    /**
     * @var string|null
     */
    private $surname;

    /**
     * @var string|null
     */
    private $emailAddress;

    /**
     * @var string|null
     */
    private $logonIdentifier;

    /**
     * @var string[]
     */
    private $roles = [];


    /**
     * @param mixed $userId
     */
    public function __construct($userId)
    {
        $this->id = $userId;
    }

    /**
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getDisplayName()
    {
        return $this->displayName;
    }

    /**
     * @param string $displayName
     * @return $this
     */
    public function setDisplayName($displayName)
    {
        $this->displayName = $displayName;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getFirstName()
    {
        return $this->firstName;
    }

    /**
     * @param string|null $firstName
     * @return $this
     */
    public function setFirstName($firstName)
    {
        $this->firstName = $firstName;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getSurname()
    {
        return $this->surname;
    }

    /**
     * @param string|null $surname
     * @return $this
     */
    public function setSurname($surname)
    {
        $this->surname = $surname;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getEmailAddress()
    {
        return $this->emailAddress;
    }

    /**
     * @param string|null $email
     * @return $this
     */
    public function setEmailAddress($email)
    {
        $this->emailAddress = $email;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getLogonIdentifier()
    {
        return $this->logonIdentifier;
    }

    /**
     * @param string|null $logonIdentifier
     * @return $this
     */
    public function setLogonIdentifier($logonIdentifier)
    {
        $this->logonIdentifier = $logonIdentifier;
        return $this;
    }

    /**
     * @return string[]
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * @param string[] $roles
     * @return $this
     */
    public function setRoles(array $roles)
    {
        $this->roles = $roles;
        return $this;
    }

    /**
     * @param string $fqn
     * @return $this
     */
    public function addRole($fqn)
    {
        $this->roles[] = $fqn;
        return $this;
    }

    /**
     * @param Acl $acl
     * @return Principal
     */
    public function getAclPrincipal(Acl $acl)
    {
        $principal = new Principal('user:'.$this->getId());
        foreach ($this->roles as $fqn)
            $principal->grantRole($acl->getRoleByFqn($fqn));

        $principal->addToAcl($acl);
        return $principal;
    }
}