<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use Codeacious\Security\SecurityService;
use Laminas\Authentication\Adapter\AdapterInterface;
use Laminas\Authentication\Result as AuthResult;
use Laminas\EventManager\AbstractListenerAggregate;
use Laminas\EventManager\EventManagerInterface;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Laminas\Mvc\MvcEvent;

/**
 * Chooses the appropriate authentication adapter for the request, authenticates, and uses the
 * result to set the current application user.
 */
class AuthenticationListener extends AbstractListenerAggregate
{
    /**
     * @var array
     */
    private $rulesConfig = [];

    /**
     * @var AdapterPluginManager
     */
    private $adapterPluginManager;

    /**
     * @var UserLookupStrategy
     */
    private $userLookupStrategy;

    /**
     * @var SecurityService
     */
    private $securityService;


    /**
     * @param array $rulesConfig
     * @return $this
     */
    public function setRulesConfig($rulesConfig)
    {
        $this->rulesConfig = $rulesConfig;
        return $this;
    }

    /**
     * @param AdapterPluginManager $adapterPluginManager
     * @return $this
     */
    public function setAdapterPluginManager($adapterPluginManager)
    {
        $this->adapterPluginManager = $adapterPluginManager;
        return $this;
    }

    /**
     * @return AdapterPluginManager
     */
    public function getAdapterPluginManager()
    {
        return $this->adapterPluginManager;
    }

    /**
     * @param UserLookupStrategy $userLookupStrategy
     * @return $this
     */
    public function setUserLookupStrategy($userLookupStrategy)
    {
        $this->userLookupStrategy = $userLookupStrategy;
        return $this;
    }

    /**
     * @return UserLookupStrategy
     */
    public function getUserLookupStrategy()
    {
        return $this->userLookupStrategy;
    }

    /**
     * @param mixed $securityService
     * @return $this
     */
    public function setSecurityService($securityService)
    {
        $this->securityService = $securityService;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function attach(EventManagerInterface $events, $priority=1)
    {
        /**
         * Request-handling event sequence is bootstrap, route, dispatch, render, finish.
         */
        $this->listeners[] = $events->attach(
            MvcEvent::EVENT_DISPATCH, array($this, 'preDispatch'), 100
        );
    }

    /**
     * @param MvcEvent $e
     * @return mixed
     */
    public function preDispatch(MvcEvent $e)
    {
        /* @var $request HttpRequest */
        $request = $e->getRequest();

        //Skip authentication for console requests or OPTIONS requests
        if (! ($request instanceof HttpRequest) || $request->isOptions())
            return null;

        $route = $e->getRouteMatch();
        $routeName = $route->getMatchedRouteName();
        $controllerName = $route->getParam('controller');
        $relPath = $this->getRelativePath($request);

        //Apply the first authentication rule that matches this request
        if (($rule = $this->getMatchingRule($relPath, $routeName, $controllerName)))
        {
            $authResult = null;
            if (!empty($rule['adapter']))
            {
                /* @var $adapter AdapterInterface */
                $adapter = $this->adapterPluginManager->get($rule['adapter']);
                $authResult = $this->authenticate($adapter, $e);
            }

            if ((!$authResult || !$authResult->isValid())
                && !empty($rule['forward_if_unauthenticated']))
            {
                $route->setMatchedRouteName(null);
                $route->setParam('controller', $rule['forward_if_unauthenticated']['controller']);
                $route->setParam('action', $rule['forward_if_unauthenticated']['action']);
                return null;
            }
        }

        return null;
    }

    /**
     * @param string $urlPath The requested URL path, relative to the base URL
     * @param string|null $routeName The name of the matched route, if there was one
     * @param string|null $controllerName The name of the controller that the matched route
     *    specified, if there was one
     * @return array|null Array of parameters for the matched rule, null if no rule matched
     */
    protected function getMatchingRule($urlPath, $routeName=null, $controllerName=null)
    {
        //Find the first authentication rule that matches this request
        foreach ($this->rulesConfig as $rule)
        {
            //Test each rule criterion. If there are multiple criteria, all must match.
            $isMatch = true;
            if (isset($rule['url_pattern']))
            {
                $regex = '/'.str_replace('/', '\/', $rule['url_pattern']).'/';
                if (!preg_match($regex, $urlPath))
                    $isMatch = false;
            }
            if (isset($rule['route_name']))
            {
                if (!is_array($rule['route_name']))
                    $rule['route_name'] = array($rule['route_name']);
                if ($routeName == null || !in_array($routeName, $rule['route_name']))
                    $isMatch = false;
            }
            if (isset($rule['controller']))
            {
                if (!is_array($rule['controller']))
                    $rule['controller'] = array($rule['controller']);
                if ($controllerName === null || !in_array($controllerName, $rule['controller']))
                    $isMatch = false;
            }

            //If this rule is a match, return its associated auth config
            if ($isMatch)
                return $rule;
        }

        return null;
    }

    /**
     * @param AdapterInterface $adapter
     * @param MvcEvent $event
     * @return AuthResult
     */
    protected function authenticate(AdapterInterface $adapter, MvcEvent $event)
    {
        $authResult = $adapter->authenticate();
        $event->setParam('AuthenticationResult', $authResult);
        if (!$authResult->isValid())
            return $authResult;

        $identity = $authResult->getIdentity();
        $event->setParam('AuthenticationIdentity', $identity);
        if (! ($identity instanceof Assertion))
        {
            return new AuthResult(AuthResult::FAILURE_UNCATEGORIZED, null,
                ['The authentication adapter result did not include an Assertion object']);
        }

        $user = $this->userLookupStrategy->getAssertedUser($identity);
        if (!$user)
        {
            return new AuthResult(AuthResult::FAILURE_IDENTITY_NOT_FOUND, null,
                ['User does not exist']);
        }

        $realUser = $this->userLookupStrategy->getRealUser($identity);
        if (!$realUser)
        {
            return new AuthResult(AuthResult::FAILURE_IDENTITY_NOT_FOUND, null,
                ['Real user could not be determined']);
        }

        $this->securityService->setCurrentUser($user);
        if ($realUser !== $user)
            $this->securityService->setOverridingAuditUser($realUser);

        return $authResult;
    }

    /**
     * Get the URI path of the request, relative to the application base URL.
     *
     * @param HttpRequest $request
     * @return string
     */
    protected function getRelativePath(HttpRequest $request)
    {
        $basePath = $request->getBasePath();
        $relPath = $request->getUri()->getPath();
        if (!empty($basePath) && strpos($relPath, $basePath) === 0)
            $relPath = substr($relPath, strlen($basePath));
        return $relPath;
    }
}