<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Controller\Plugin;

use Codeacious\Security\Authentication\Assertion;
use Laminas\Mvc\Controller\AbstractController;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;

class AuthAssertion extends AbstractPlugin
{
    /**
     * @return Assertion|null
     */
    public function __invoke()
    {
        $controller = $this->getController();
        if ($controller instanceof AbstractController)
        {
            $identity = $controller->getEvent()->getParam('AuthenticationIdentity', null);
            if ($identity instanceof Assertion)
                return $identity;
        }
        return null;
    }
}