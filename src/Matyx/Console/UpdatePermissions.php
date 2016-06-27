<?php

namespace Matyx\Console;

use Nette\Neon\Neon;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Tracy\Debugger;

class UpdatePermissions extends Command {

	/**
	 * Configures the current command.
	 */
	protected function configure() {
		$this->setName("zalozka:update-permissions")
			->setDescription("Updates permissions by config")
			->addArgument('filename', InputArgument::REQUIRED);
	}

	/**
	 * Executes the current command.
	 *
	 * This method is not abstract because you can use this class
	 * as a concrete class. In this case, instead of defining the
	 * execute() method, you set the code to execute by passing
	 * a Closure to the setCode() method.
	 *
	 * @param InputInterface $input An InputInterface instance
	 * @param OutputInterface $output An OutputInterface instance
	 *
	 * @return null|int null or 0 if everything went fine, or an error code
	 *
	 * @throws \LogicException When this abstract method is not implemented
	 *
	 * @see setCode()
	 */
	protected function execute(InputInterface $input, OutputInterface $output) {
		Debugger::enable(Debugger::DEVELOPMENT);

		$db = $this->getHelper('container')->getByType('Nette\Database\Context');
		$db->query("BEGIN");

		$filename = $input->getArgument("filename");
		$output->writeln("Opening file " . $filename);

		if(!is_file($filename)) {
			$output->writeln("<error>Can't read file</error>");

			return 1;
		}

		$perms = Neon::decode(file_get_contents($filename));

		$db->query("SET FOREIGN_KEY_CHECKS = 0");
		$db->query("TRUNCATE TABLE permission");
		$db->query("TRUNCATE TABLE resource");
		$db->query("TRUNCATE TABLE role");
		$db->query("SET FOREIGN_KEY_CHECKS = 1");

		$id = 1;
		foreach($perms['roles'] as $role => $v) {
			$output->writeln('Creating role ' . $role);
			$roles[$role] = $id;
			$db->query("INSERT INTO role SET id = ?, name = ?, title = ?, parent_id = ?", $id, $role, $v['title'], (isset($v['parent']) ? $roles[$v['parent']] : NULL));
			$id++;
		}

		$id = 1;
		foreach($perms['resources'] as $resource) {
			$output->writeln('Creating resource ' . $resource);
			$resources[$resource] = $id;
			$db->query('INSERT INTO resource SET id = ?, name = ?', $id, $resource);
			$id++;
		}

		foreach($perms['permissions'] as $role => $p) {
			foreach($p as $resource => $actions) {

				foreach($actions as $action => $permission) {
					$output->writeln("Setting permission: $role:$resource:$action:" . ($permission ? 'allow' : 'deny'));
					$db->query('INSERT INTO permission SET role_id = ?, resource_id = ?, action = ?, type = ?', $roles[$role], $resources[$resource], $action, ($permission ? 'allow' : 'deny'));
				}
			}
		}

		$db->query('COMMIT');
	}

}