<?php

namespace Matyx\Authorizators;

use Nette;
use Nette\Caching\Cache;
use Nette\Caching\IStorage;
use Nette\Database\Context;
use Nette\Security\Permission;
use Nette\Security\privilege;
use Nette\Security\role;

class Authorizator extends Nette\Object implements Nette\Security\IAuthorizator {
	/** @var Permission  */
	protected $acl;

	/** @var Context */
	protected $db;

	/**
	 * Authorizator constructor.
	 *
	 * @param Context $db
	 * @param IStorage $cacheStorage
	 */
	public function __construct(Context $db, IStorage $cacheStorage) {
		$this->db = $db;

		$cache = new Cache($cacheStorage, 'permissions');

		$this->acl = $cache->load('acl', function(& $dependencies) use ($db) {
			$dependencies[Cache::EXPIRE] = '1 day';
			$acl = new Permission;

			foreach($db->query("SELECT r.name, rr.name AS parent FROM role AS r LEFT JOIN role AS rr ON (r.parent_id = rr.id) ORDER BY r.id ASC") as $role) {
				$acl->addRole($role->name, $role->parent);
			}

			foreach($db->query("SELECT * FROM resource") as $resource) {
				$acl->addResource($resource->name);
			}

			$acl->allow('admin');

			foreach($db->query("SELECT role.name AS role, resource.name AS resource, permission.action AS action, permission.type as type FROM permission JOIN resource ON (resource.id = permission.resource_id) JOIN role ON (permission.role_id = role.id)") as $permission) {
				if($permission->type == 'allow') {
					$acl->allow($permission->role, $permission->resource, $permission->action);
				} else {
					$acl->deny($permission->role, $permission->resource, $permission->action);
				}
			}

			return $acl;
		});
	}


	/**
	 * Performs a role-based authorization.
	 *
	 * @param  string  role
	 * @param  string  resource
	 * @param  string  privilege
	 * @return bool
	 */
	public function isAllowed($role = self::ALL, $resource = self::ALL, $privilege = self::ALL) {
		return $this->acl->isAllowed($role, $resource, $privilege);
	}
}