
	// Set CSRF token
	axios.defaults.headers.common['X-CSRFToken'] =
	window._application_csrfmiddlewaretoken; // for all requests

	// Global store used by Vue elements
	var store = {
		show_logins_table: false,
		should_add_login: false,
		temporary_key: "",
		login_to_modify: {},
		logins_list: [],
	};

	// Vue element to execute login
	var appDoLogin = new Vue({
		el: '#appDoLogin',
		delimiters: ['[[', ']]'],
		data: {
			user_password: "",
			login_error_message: "",
			show_error_message: false,
			shared: store
		},
		methods: {
			invokeLoginModal: function () {
				// Shows error field if is being brought up by 403 error
				if(this.shared.temporary_key != ''){
					appDoLogin.showError(
						"Your session has expired. Please login again!"
					);
				}
				// Shows modal
				var popup = new Foundation.Reveal($('#doLogin'));
				popup.open();
			},

			redirectToMain: function () {
				window.location.href = '/';
			},

			executeLogin: function () {
				var urlToUse = 'user/' + window._application_user_id
				+ '/temporary_key/';

				// Execute request to server and handle response
				axios.post(
					urlToUse,
					{
						password: this.user_password
					}
				).then(function(response){
					// Clears all fields
					appDoLogin.login_error_message = "";
					appDoLogin.show_error_message = false;
					appDoLogin.user_password = "";

					// Tells apps to show logins table and store temporary key locally
					appDoLogin.shared.show_logins_table = true;
					appDoLogin.shared.temporary_key = response.data.temporary_key;

					// Dismiss login modal
					$('#doLogin').foundation('close');
				}).catch(function (error){
					if (error.response) {
						appDoLogin.showError(
							"Password is incorrect or user is not allowed!"
						);
					}
				});
			},

			showError: function(message){
				appDoLogin.login_error_message = message;
				appDoLogin.show_error_message = true;
			},

		},

		mounted: function () {
			this.invokeLoginModal();
		}

	});

	// Vue element to handle logins table
	var appLoginsViewer = new Vue({
		el: '#appLoginsViewer',
		delimiters: ['[[', ']]'],
		data: {
			shared: store
		},

		watch: {
			// When we have the temporary key, we can get all logins from server
	    "shared.temporary_key": function (val) {
				this.getLoginsList();
	    }
	  },

		methods: {
			invokeAddLoginModal: function () {
				// Shows modal
				var popup = new Foundation.Reveal($('#appAddOrChangeLogin'));
				popup.open();
			},

			getLoginsList: function() {
				var urlToUse = 'user/' + window._application_user_id
				+ '/password/';

				// Execute request to server and handle response
				axios.get(
					urlToUse,
					{
						headers: {
							Authorization: appLoginsViewer.shared.temporary_key
						}
					}
				).then(function(response){
					// Saves the list of logins
					appLoginsViewer.shared.logins_list = response.data;
					// Adds cosmetic elements to the list
					var i;
					for (i = 0; i < appLoginsViewer.shared.logins_list.length; i++) {
						// Adds password field
				    appLoginsViewer.shared.logins_list[i].password = "**************************";
						appLoginsViewer.shared.logins_list[i].hovering_password = false;
						// Adds passwordTypeField
				    appLoginsViewer.shared.logins_list[i].password_field_type = "password";
				    appLoginsViewer.shared.logins_list[i].buttonText = "Show";
					}
				}).catch(function (error){
					if (error.response) {
						// Here is not possible to have an 403 error, so we do not handle it
						alert("Something went wrong while retrieving your logins!");
					}
				});
			},

			updateLoginEntryPassword: function(idx, loginEntry) {
				var urlToUse = 'user/' + window._application_user_id
				+ '/password/' + loginEntry.id + '/';

				// Execute request to server and handle response
				axios.get(
					urlToUse,
					{
						headers: {
							Authorization: appLoginsViewer.shared.temporary_key
						}
					}
				).then(function(response){
						// Updates the revealed password
						loginEntry.password = response.data.password;
						loginEntry.buttonText = 'Hide';
						loginEntry.password_field_type = 'text';
						loginEntry.hovering_password = false;
						// Here we have to use Vue.set due to limitations
						Vue.set(appLoginsViewer.shared.logins_list, idx, loginEntry);
				}).catch(function (error){
					if (error.response) {

						if (error.response.status === 403){
							// Temporary Key has expired; asks user to login again
							window.location.href = '/logins/';
						}
						else{
							alert("Something went wrong while retrieving this password!"
								+ " Please try again");
						}

					}
				});
			},

			revealPassword: function(idx, loginEntry) {
				// Updates button text and input field type
				if(loginEntry.buttonText === 'Show'){
					// Gets password and updates fields
					this.updateLoginEntryPassword(idx, loginEntry);
				}
				else{
					loginEntry.password = "**************************";
					loginEntry.buttonText = 'Show';
					loginEntry.password_field_type = 'password';
					// Here we have to use Vue.set due to limitations
					Vue.set(appLoginsViewer.shared.logins_list, idx, loginEntry);
				}
			},

			onChangeLoginEntry:function(login){
				// We store which login entry we want ot modify
				this.shared.login_to_modify = login;
				this.shared.should_add_login = false;

				// We tell the add or change password modal to fill their fields
				appAddOrChangeLogin.fillFields();
			},

			onDeleteLoginEntry:function(login){
				// We store which login entry we want ot modify
				this.shared.login_to_modify = login;
			},

			toggleHoverPassword: function(is_hovering, idx, loginEntry) {
				loginEntry.hovering_password = is_hovering;
				// Here we have to use Vue.set due to limitations
				Vue.set(appLoginsViewer.shared.logins_list, idx, loginEntry);
			},

			canShowCopyButton: function(login){
				return (login.hovering_password) && (login.password_field_type === 'text');
			},

			copyToClipboard: function(loginEntry) {
				// Create a dummy input to copy the variable inside it
				var dummy = document.createElement("input");
				document.body.appendChild(dummy);
				dummy.setAttribute("id", "dummy_id");
				// Put the password value inside it
				document.getElementById("dummy_id").value=loginEntry.password;
				// Copy content to clipboard
				dummy.select();
				document.execCommand("copy");
				document.body.removeChild(dummy);
			},

		}

	});

	// Vue element to execute login
	var appAddOrChangeLogin = new Vue({
		el: '#appAddOrChangeLogin',
		delimiters: ['[[', ']]'],
		data: {
			organization_name: "",
			login_url: "",
			user_name: "",
			new_password: "",
			aoc_error_message: "",
			show_aoc_error_message: false,
			shared: store
		},

		methods: {
			addLoginEntry: function () {
				var urlToUse = 'user/' + window._application_user_id
				+ '/password/';

				// Execute request to server and handle response
				axios.post(
					urlToUse,
					{
						organization: appAddOrChangeLogin.organization_name,
						url: appAddOrChangeLogin.login_url,
						username: appAddOrChangeLogin.user_name,
						password: appAddOrChangeLogin.new_password
					},
					{
						headers: {
							Authorization: appAddOrChangeLogin.shared.temporary_key
						}
					}
				).then(function(response){
					// Add returned login entry to logins list
					var new_entry = response.data;
					new_entry.password = "**************************";
					new_entry.password_field_type = "password";
					new_entry.buttonText = "Show";
					new_entry.hovering_password= false;
					appAddOrChangeLogin.shared.logins_list.push(new_entry);

					// Clear fields of modal
					appAddOrChangeLogin.clearFields();

					// Dismiss login modal
					$('a.close-button').trigger('click');
				}).catch(function (error){
					if (error.response) {
						if (error.response.status === 403){
							// Clear fields of modal
							appAddOrChangeLogin.clearFields();
							// Temporary Key has expired; asks user to login again
							window.location.href = '/logins/';
						}
						else{
							alert("Something went wrong while creating login entry!");
						}
					}
				});
			},

			changeLoginEntry: function () {
				var urlToUse = 'user/' + window._application_user_id
				+ '/password/' + appDeleteLogin.shared.login_to_modify.id + '/';

				// Execute request to server and handle response
				axios.put(
					urlToUse,
					{
						organization: appAddOrChangeLogin.organization_name,
						url: appAddOrChangeLogin.login_url,
						username: appAddOrChangeLogin.user_name,
						password: appAddOrChangeLogin.new_password
					},
					{
						headers: {
							Authorization: appAddOrChangeLogin.shared.temporary_key
						}
					}
				).then(function(response){
					// Request went successful, change login entry from logins_list
					var index = appAddOrChangeLogin.shared.logins_list.indexOf(
						appAddOrChangeLogin.shared.login_to_modify);
					if (index > -1) {
						var loginEntry = appAddOrChangeLogin.shared.logins_list[index];
						loginEntry.organization = appAddOrChangeLogin.organization_name,
						loginEntry.url = appAddOrChangeLogin.login_url,
						loginEntry.username = appAddOrChangeLogin.user_name,
						loginEntry.password = appAddOrChangeLogin.new_password
						// Here we have to use Vue.set due to limitations
						Vue.set(appAddOrChangeLogin.shared.logins_list, index, loginEntry);
					}

					// Clear fields of modal
					appAddOrChangeLogin.clearFields();

					// Dismiss login modal
					$('a.close-button').trigger('click');
				}).catch(function (error){
					if (error.response) {
						if (error.response.status === 403){
							// Clear fields of modal
							appAddOrChangeLogin.clearFields();
							// Temporary Key has expired; asks user to login again
							window.location.href = '/logins/';
						}
						else{
							alert("Something went wrong while changing login entry!");
						}
					}
				});
			},

			addOrChangeLoginEntry: function(){
				// we validate  the form before we change for add a login
				if(!this.validateFields()){
					return;
				}

				// If fields are validated, we do a server request
				if(this.shared.should_add_login){
					this.addLoginEntry();
				}
				else{
					this.changeLoginEntry();
				}
			},

			validateFields: function(){
				// Expressions for Login URL
				var expression = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%_\+.~#?&//=]{2,256}\.[a-z]{2,4}\b(\/[-a-zA-Z0-9@:%_\+.~#?&//=]*)?/gi;
				var regex = new RegExp(expression);

				// Organization name
				if(this.organization_name == ''){
					this.showError("Organization name must not be empty");
					return false;
				}
				else if (!this.login_url.match(regex)) {
					this.showError("Login should be a valid URL such as http://example.com");
					return false;
				}
				// User name
				else if (this.user_name == '') {
					this.showError("User name must not be empty");
					return false;
				}
				// Password
				else if (this.new_password == '') {
					this.showError("Password must not be empty");
					return false;
				}
				else{
					return true;
				}
			},

			fillFields: function(){
				// Fill the modal fields with the login entry values selected
				this.organization_name = this.shared.login_to_modify.organization;
				this.login_url = this.shared.login_to_modify.url;
				this.user_name = this.shared.login_to_modify.username;
				//this.new_password = this.shared.login_to_modify.password;
			},

			clearFields: function(){
				this.organization_name = "";
				this.login_url = "";
				this.user_name = "";
				this.new_password = "";
				this.aoc_error_message = "";
				this.show_aoc_error_message = false;
			},

			showError: function(message){
				this.aoc_error_message = message;
				this.show_aoc_error_message = true;
			},

		}

	});

	// Vue element to execute login
	var appDeleteLogin = new Vue({
		el: '#appDeleteLogin',
		delimiters: ['[[', ']]'],
		data: {
			shared: store
		},
		methods: {
			deleteLoginEntry: function() {
				var urlToUse = 'user/' + window._application_user_id
				+ '/password/' + appDeleteLogin.shared.login_to_modify.id + '/';

				// Execute request to server and handle response
				axios.delete(
					urlToUse,
					{
						headers: {
							Authorization: appDeleteLogin.shared.temporary_key
						}
					}
				).then(function(response){
					// Request went successful, delete login entry from logins_list
					var index = appDeleteLogin.shared.logins_list.indexOf(
						appDeleteLogin.shared.login_to_modify);
					if (index > -1) {
					  appDeleteLogin.shared.logins_list.splice(index, 1);
					}

					// Dismiss login modal
					$('a.close-button').trigger('click');
				}).catch(function (error){
					if (error.response) {
						if (error.response.status === 403){
						// Temporary Key has expired; asks user to login again
						window.location.href = '/logins/';
						}
						else{
							alert("Something went wrong while deleting login entry!");
						}
					}
				});
			},
		},

	});
