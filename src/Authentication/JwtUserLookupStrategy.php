<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use Codeacious\Security\BasicUser;

/**
 * Creates a virtual user object from the claims in a JWT assertion (no lookups required).
 */
class JwtUserLookupStrategy implements UserLookupStrategy
{
    /**
     * @var string
     */
    private $userClass;


    public function __construct(string $userClass=BasicUser::class)
    {
        $this->userClass = $userClass;
    }

    /**
     * @param Assertion $assertion
     * @return \Codeacious\Security\User|null
     */
    public function getAssertedUser(Assertion $assertion)
    {
        $user = $this->createUserObject($assertion->getUserId());
        if ($assertion instanceof JwtAssertion)
        {
            $user->setDisplayName($assertion->getDisplayName())
                ->setFirstName($assertion->getFirstName())
                ->setSurname($assertion->getSurname())
                ->setEmailAddress($assertion->getEmailAddress())
                ->setLogonIdentifier($assertion->getClaim('preferred_username'))
                ->setRoles($assertion->getClaim('roles', []));
        }
        return $user;
    }

    /**
     * @param Assertion $assertion
     * @return \Codeacious\Security\User|null
     */
    public function getRealUser(Assertion $assertion)
    {
        $realUserId = $assertion->getRealUserId();
        if (empty($realUserId))
            return $this->getAssertedUser($assertion);

        return $this->createUserObject($realUserId);
    }

    /**
     * @param mixed $userId
     * @return BasicUser
     */
    protected function createUserObject($userId)
    {
        $class = $this->userClass;
        return new $class($userId);
    }
}