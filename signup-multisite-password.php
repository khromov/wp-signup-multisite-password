<?php
/*
Plugin Name: Set password on Multisite Registration
Plugin URI:
Description: Lets users set a password on multisite registration
Author: khromov, WPMUDEV
Version: 2014.06.03
Author URI: http://premium.wpmudev.org/
Network: true
Text Domain: multisite_password_registration
*/

/* Don't do anything unless multisite */
if(is_multisite())
{
	/** Load textdomain **/
	add_action('init', function()
	{
		load_plugin_textdomain('multisite_signup_pw', false, dirname(plugin_basename(__FILE__)).'/languages');
	});

	/** Extra signup field **/
	add_action('signup_extra_fields', function($errors)
	{
		//Find errors
		if($errors && method_exists($errors, 'get_error_message'))
			$error = $errors->get_error_message('password_1');
		else
			$error = false;
		?>

		<!-- Label for password_1 -->
		<label for="password_1"><?=__('Password', 'multisite_signup_pw')?>:</label>

		<!-- Errors -->
		<?=($error) ? "<p class=\"error\">{$error}</p>" : ''?>

		<!-- password_1 input -->
		<input name="password_1" type="password" id="password_1" value="" autocomplete="off" maxlength="20"/><br/>
		<?=__('Type in your password.', 'multisite_signup_pw')?>

		<!-- Label for password_2 -->
		<label for="password_2"><?=__('Confirm Password', 'multisite_signup_pw'); ?>:</label>

		<!-- password_2 input -->
		<input name="password_2" type="password" id="password_2" value="" autocomplete="off" maxlength="20"/><br/>
		<?=__('Type in your password again.', 'multisite_signup_pw')?>
		<?php
	}, 9); //Show early

	/** Perform field validation **/
	add_filter('wpmu_validate_user_signup', function($content)
	{
		$password_1 = isset($_POST['password_1']) ? $_POST['password_1'] : '';
		$password_2 = isset($_POST['password_2']) ? $_POST['password_2'] : '';

		if(isset($_POST['stage']) && $_POST['stage'] == 'validate-user-signup')
		{
			//No primary password entered
			if(trim($password_1) === '')
			{
				$content['errors']->add('password_1', __('You have to enter a password.', 'multisite_signup_pw'));
				return $content;
			}

			//Passwords do not match
			if($password_1 != $password_2)
			{
				$content['errors']->add('password_1', __('Passwords do not match.', 'multisite_signup_pw'));
				return $content;
			}
		}

		//No errors, yay!
		return $content;
	});

	/** Add password to temporary user meta **/
	add_filter('add_signup_meta', function($meta)
	{
		if(isset($_POST['password_1']))
		{
			$add_meta = array('password' => base64_encode($_POST['password_1'])); //Store as base64 to avoid injections
			$meta = array_merge($add_meta, $meta);
		}
		//This should never happen.

		return $meta;
	}, 99);

	/** Pass the password through to the blog registration form **/
	add_action('signup_blogform', function()
	{
		if(isset($_POST['password_1']))
		{
			?>
			<input type="hidden" name="password_1" value="<?php echo $_POST['password_1']; ?>" />
			<?php
		}
	});

	/** Override wp_generate_password() once when we're generating our form **/
	add_filter('random_password', function($password)
	{
		global $wpdb;

		//Check key in GET and then fallback to POST.
		if(isset($_GET['key']))
			$key = $_GET['key'];
		else if(isset($_POST['key']))
			$key = $_POST['key'];
		else
			$key = null;

		//Look for active signup
		$signup = $wpdb->get_row($wpdb->prepare("SELECT * FROM $wpdb->signups WHERE activation_key = '%s'", $key));

		//Only override filter on wp-activate.php screen
		if(strpos($_SERVER['PHP_SELF'], 'wp-activate.php') && $key !== null && (!(empty($signup) || $signup->active)))
		{
			$meta = maybe_unserialize($signup->meta);
			if(isset($meta['password']))
			{
				//Set the "random" password to our predefined one
				$password = base64_decode($meta['password']);

				//Remove old password from signup meta (As it doesn't appear to get deleted.)
				unset($meta['password']);
				$meta = maybe_serialize( $meta );
				$wpdb->update($wpdb->signups, array( 'meta' => $meta ), array( 'activation_key' => $key ), array( '%s' ), array( '%s' ));

				return $password;
			}
			else
				return $password; //No password meta set = just activate user as normal with random password
		}
		else
			return $password; //Regular usage, don't touch the password generation
	});
}