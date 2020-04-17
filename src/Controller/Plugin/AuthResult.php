<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Controller\Plugin;

use Laminas\Authentication\Result;
use Laminas\Mvc\Controller\AbstractController;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;

class AuthResult extends AbstractPlugin
{
    /**
     * @return Result|null
     */
    public function __invoke()
    {
        $controller = $this->getController();
        if ($controller instanceof AbstractController)
        {
            return $controller->getEvent()->getParam('AuthenticationResult', null);
        }
        return null;
    }
}