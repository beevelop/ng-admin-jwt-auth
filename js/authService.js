var ngAdminJWTAuthService = function($http, jwtHelper, ngAdminJWTAuthConfigurator, $rootScope) { 
	
	return {
		authenticate: function(data, successCallback, errorCallback) {
			var url = ngAdminJWTAuthConfigurator.getAuthURL();

			return $http({
				url: url,
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				data: data
			}).then(function(response) {
				var payload = jwtHelper.decodeToken(response.data.token);
				
				localStorage.userToken = response.data.token;
				localStorage.userRole = payload.role;
				$rootScope.jwtPayload = payload;
				
				successCallback(response); 
				
				var customAuthHeader = ngAdminJWTAuthConfigurator.getCustomAuthHeader();
				if (customAuthHeader) {
					$http.defaults.headers.common[customAuthHeader.name] = customAuthHeader.template.replace('{{token}}', response.data.token);
				} else {
					$http.defaults.headers.common.Authorization = 'Basic ' + response.data.token;
				}
			} , errorCallback);
		},
		
		isAuthenticated: function() {
			var token = localStorage.userToken;
			if (!token) {
				return false;
			}
			return jwtHelper.isTokenExpired(token) ? false : true;
		},

		getTokenPayload: function () {
			var token = localStorage.userToken
			if (token && !jwtHelper.isTokenExpired(token)) {
				return jwtHelper.decode(token)
			}

			return false
		},
		
		logout: function() {
			localStorage.removeItem('userRole');
			localStorage.removeItem('userToken');
			return true;
		}
	}
	
};

ngAdminJWTAuthService.$inject = ['$http', 'jwtHelper', 'ngAdminJWTAuthConfigurator', '$rootScope'];

module.exports = ngAdminJWTAuthService;