<?php

namespace obray;

if (!class_exists(\obray\oObject::class)) {
    die();
}

/**
 * oUsers
 *
 * User/Permission Manager
 */
Class oUsers extends \obray\oDBO
{

    private $max_failed_login_attempts = 10;
    protected $table = 'oUsers';
    protected $table_definition = array(
        'ouser_id' => array('primary_key' => true),
        'ouser_first_name' => array('data_type' => 'varchar(128)', 'required' => false),
        'ouser_last_name' => array('data_type' => 'varchar(128', 'required' => false),
        'ouser_email' => array('data_type' => 'varchar(128)', 'required' => true),
        'ouser_permission_level' => array('data_type' => 'integer', 'required' => false),
        'ouser_status' => array('data_type' => 'varchar(20)', 'required' => false),
        'ouser_password' => array('data_type' => 'password', 'required' => true),
        'ouser_failed_attempts' => array('data_type' => 'integer', 'required' => false),
        'ouser_last_login' => array('data_type' => 'datetime', 'required' => false),
        'ouser_settings' => array('data_type' => 'text', 'required' => false)
    );

    protected $permissions = array(
        'object' => 'any',
        'add' => 'any',
        'get' => 1,
        'update' => 1,
        'login' => 'any',
        'logout' => 'any',
        'count' => 1,
        'getRolesAndPermissions' => 1,
        'blah' => 1
    );

    public function __construct()
    {

        $dependencies = include "dependencies/config.php";
        forEach ($dependencies as $key => $dependency) {
            if ($key !== 'oUsers') {
                $this->$key = $dependency;
            }
        }

        return $this;

    }

    public function add($params = array())
    {

        if (empty($params["ouser_active"])) {
            $params["ouser_active"] = true;
        }

        if (empty($params["ouser_permission_level"])) {
            $params["ouser_permission_level"] = 1;
        }

        if (empty($params["ouser_failed_attempts"])) {
            $params["ouser_failed_attempts"] = 0;
        }

        parent::add($params);

    }

    /**
     * Login
     * creates the ouser session variable
     *
     * @param string $oUserEmail
     * @param string $oUserPassword
     */
    public function login($ouser_email = '', $ouser_password = '')
    {
        // Validate the required parameters
        if (empty($ouser_email)) {
            $this->throwError('Email is required', 500, 'ouser_email');
        }
        if (empty($ouser_password)) {
            $this->throwError('Password is required', 500, 'ouser_password');
        }
        if ($this->isError()) {
            return;
        }
        
        // get user based on credentials
        $response = $this->get(array(
            'ouser_email' => $ouser_email,
            'ouser_password' => $ouser_password
        ));
        
        // if the user exists log them in but only if they haven't exceed the max number of failed attempts (set in settings)
        if (count($this->data) === 1 && $this->data[0]->ouser_failed_attempts < $this->max_failed_login_attempts && $this->data[0]->ouser_status != 'disabled') {
            $this->data[0]->ouser_settings = unserialize(base64_decode($this->data[0]->ouser_settings));
            $this->oSession->{$this->user_session_key} = $this->data[0];
            $this->getRolesAndPermissions();
            $this->update(array(
                'ouser_id' => $this->oSession->{$this->user_session_key}->ouser_id,
                'ouser_failed_attempts' => 0,
                'ouser_last_login' => date('Y-m-d H:i:s')
            ));
            
            return $this->oSession->get()->oUser;
        }

        // if the data is empty (no user is found with the provided credentials)
        if (empty($this->data)) {

            $this->get(array('ouser_email' => $params['ouser_email']));
            if (count($this->data) === 1) {
                $this->update(array(
                    'ouser_id' => $this->data[0]->ouser_id,
                    'ouser_failed_attempts' => ($this->data[0]->ouser_failed_attempts + 1)
                ));
                $this->data = array();
            }
            return $this->throwError('Invalid login, make sure you have entered a valid email and password.');
        }

        // if the user has exceeded the allowable login attempts
        if ($this->data[0]->ouser_failed_attempts > $this->max_failed_login_attempts) {
            return $this->throwError('This account has been locked.');
        }

        // if the user has been disabled
        if ($this->data[0]->ouser_status === 'disabled') {
            return $this->throwError('This account has been disabled.');
        }

        // if the user is not found then increment failed attempts and throw error
        $this->get(array('ouser_email' => $params['ouser_email']));
        if (count($this->data) === 1) {
            $this->update(array(
                'ouser_id' => $this->data[0]->ouser_id,
                'ouser_failed_attempts' => ($this->data[0]->ouser_failed_attempts + 1)
            ));
        }
        return $this->throwError('Invalid login, make sure you have entered a valid email and password.');

    }

    /********************************************************************************************************************
     *
     * Logout - destroys the ouser session variable
     ********************************************************************************************************************/

    public function logout($params=array())
    {
        unset($this->oSession->{$this->user_session_key});
        $this->oSession->clear();
        $this->data['logout'] = true;
    }

    public function authorize($params = array())
    {

        if (!isSet($this->oSession->{$this->user_session_key})) {
            $this->throwError('Forbidden', 403);
        } else {
            if (isSet($params['level']) && $params['level'] < $this->oSession->{$this->user_session_key}->ouser_permission_level) {
                $this->throwError('Forbidden', 403);
            }
        }

    }

    public function hasPermission($object)
    {
        if (isSet($this->permissions[$object]) && $this->permissions[$object] === 'any') {
            return true;
        } else {
            return false;
        }
    }

    public function setting($params = array())
    {

        if (!empty($params) && !empty($this->oSession->{$this->user_session_key}->ouser_id)) {

            if (!empty($params['key']) && isSet($params['value'])) {

                $this->oSession->{$this->user_session_key}->ouser_settings[$params['key']] = $params['value'];

                $this->route('/obray/OUsers/update/?ouser_id=' . $this->oSession->{$this->user_session_key}->ouser_id . '&ouser_settings=' . base64_encode(serialize($this->oSession->{$this->user_session_key}->ouser_settings)));

            } else {
                if (!empty($params['key'])) {

                    $this->data[$params['key']] = $this->oSession->{$this->user_session_key}->ouser_settings[$params['key']];

                }
            }

        }

    }

    /************************************************************
     *
     * Get Roles & Permission
     ************************************************************/

    public function getRolesAndPermissions()
    {

        if (!empty($this->oSession->{$this->user_session_key}->ouser_id)) {

            $sql = "SELECT oPermissions.opermission_code, oRoles.orole_code
							FROM oUserRoles
							JOIN oRoles ON oRoles.orole_id = oUserRoles.orole_id
						LEFT JOIN oRolePermissions ON oRolePermissions.orole_id = oUserRoles.orole_id
							JOIN oPermissions ON oPermissions.opermission_id = oRolePermissions.opermission_id
							WHERE oUserRoles.ouser_id = :ouser_id
					
					UNION 
					
						SELECT oPermissions.opermission_code, NULL AS orole_code
							FROM oUserPermissions
							JOIN oPermissions ON oPermissions.opermission_id = oUserPermissions.opermission_id
							WHERE oUserPermissions.ouser_id = :ouser_id";

            try {

                $statement = $this->oDBOConnection->connect()->prepare($sql);
                $statement->bindValue(':ouser_id', $this->oSession->{$this->user_session_key}->ouser_id);
                $result = $statement->execute();
                $this->data = [];
                $statement->setFetchMode(\PDO::FETCH_OBJ);
                while ($row = $statement->fetch()) {
                    $this->data[] = $row;
                }

                $roles = array();
                $permissions = array();
                forEach ($this->data as $codes) {
                    if (!empty($codes->orole_code) && !in_array($codes->orole_code, $roles)) {
                        $roles[] = $codes->orole_code;
                    }
                    if (!empty($codes->opermission_code) && !in_array($codes->opermission_code, $permissions)) {
                        $permissions[] = $codes->opermission_code;
                    }
                }

                if (!empty($this->oSession->{$this->user_session_key})) {
                    $this->oSession->{$this->user_session_key}->permissions = $permissions;
                    $this->oSession->{$this->user_session_key}->roles = $roles;
                }

                $this->data = array(
                    "permissions" => $permissions,
                    "roles" => $roles
                );

            } catch (\PDOException $e) {

                if (!empty($e->errorInfo[1]) && $e->errorInfo[1] == 1146) {
                    $this->scriptOnMissingTable($e);


                }

            }

        }

    }
    
    public function setPermissions($permissions)
    {
        $this->permissions = $permissions;
    }

}

?>