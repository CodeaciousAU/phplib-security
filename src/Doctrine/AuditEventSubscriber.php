<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Doctrine;

use Codeacious\Model\AbstractEntity;
use Codeacious\Security\SecurityService;
use Doctrine\Common\EventArgs;
use Doctrine\Common\EventSubscriber;
use Doctrine\Common\NotifyPropertyChanged;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\UnitOfWork;
use Doctrine\Persistence\Mapping\ClassMetadata;

/**
 * Doctrine plugin which sets audit fields when an entity is created or updated.
 *
 * To use it, register it with your Doctrine EventManager:
 * <pre>
 * 'doctrine' => [
 *     'eventmanager' => [
 *         'orm_default' => [
 *             'subscribers' => [
 *                 Codeacious\Security\Doctrine\AuditEventSubscriber::class,
 * ..
 * </pre>
 */
class AuditEventSubscriber implements EventSubscriber
{
    /**
     * @var SecurityService
     */
    protected $securityService;


    /**
     * @param SecurityService $securityService
     * @return AuditEventSubscriber
     */
    public function setSecurityService($securityService)
    {
        $this->securityService = $securityService;
        return $this;
    }
    
    /**
     * Specifies the list of events to listen for.
     *
     * @return array
     */
    public function getSubscribedEvents()
    {
        return array('onFlush');
    }
    
    /**
     * Called when changes are about to be flushed to the database.
     * 
     * @param EventArgs $args
     * @return void
     */
    public function onFlush(EventArgs $args)
    {
        $em = $args->getEntityManager(); /* @var $em \Doctrine\ORM\EntityManager */
        $uow = $em->getUnitOfWork(); /* @var $uow \Doctrine\ORM\UnitOfWork */
        
        foreach ($uow->getScheduledEntityUpdates() as $entity)
        {
            if ($entity instanceof AbstractEntity)
                $this->processEntity($entity, $em, $uow);
        }
        
        foreach ($uow->getScheduledEntityInsertions() as $entity)
        {
            if ($entity instanceof AbstractEntity)
                $this->processEntity($entity, $em, $uow);
        }
    }
    
    /**
     * @param AbstractEntity $entity
     * @param EntityManager $em
     * @param UnitOfWork $uow
     * @return void
     */
    protected function processEntity(AbstractEntity $entity, EntityManager $em, UnitOfWork $uow)
    {
        $metadata = $em->getClassMetadata(get_class($entity));
        $changeSet = $uow->getEntityChangeSet($entity);
        $hasChanges = false;
        
        if (!isset($changeSet['lastUpdateDate']) || empty($changeSet['lastUpdateDate'][1]))
        {
            $hasChanges = true;
            $this->updateField(
                $entity, $uow, $metadata,
                'lastUpdateDate',
                new \DateTime()
            );
        }
        if (!isset($changeSet['lastUpdateUserId']) || empty($changeSet['lastUpdateUserId'][1]))
        {
            $hasChanges = true;
            $this->updateField(
                $entity, $uow, $metadata,
                'lastUpdateUserId',
                $this->securityService->getCurrentAuditUserId()
            );
        }

        if ($hasChanges)
            $uow->recomputeSingleEntityChangeSet($metadata, $entity);
    }
    
    /**
     * @param AbstractEntity $entity
     * @param UnitOfWork $uow
     * @param ClassMetadata $metadata
     * @param string $field
     * @param mixed $newValue
     * @return void
     */
    protected function updateField(AbstractEntity $entity, UnitOfWork $uow, ClassMetadata $metadata,
        $field, $newValue)
    {
        $property = $metadata->getReflectionClass()->getProperty($field);
        $property->setAccessible(true);
        $oldValue = $property->getValue($entity);
        $property->setValue($entity, $newValue);
        
        if ($entity instanceof NotifyPropertyChanged)
            $uow->propertyChanged($entity, $field, $oldValue, $newValue);
    }
}
