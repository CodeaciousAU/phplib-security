<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */
namespace Codeacious\Security;

/**
 * The module class.
 */
class Module
{
    /**
     * @return array|null
     */
    public function getConfig()
    {
        return include __DIR__.'/../config/module.config.php';
    }
}
