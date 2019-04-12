<?

	class SymconTesla extends IPSModule {
		
		static $APIBASE = "https://owner-api.teslamotors.com";

		static $CLIENTID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384";
		static $CLIENTSECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3";
		
		public function Create() {
			//Never delete this line!
			parent::Create();
			
			$this->RegisterPropertyString("Token", "");
			$this->RegisterPropertyString("RefreshToken", "");
			$this->RegisterPropertyString("User", "");
			$this->RegisterPropertyString("Password", "");

		}
	
		public function ApplyChanges() {
			//Never delete this line!
			parent::ApplyChanges();
			
			//$this->RegisterOAuth();
		}
		/*
		private function RegisterOAuth() {
			$ids = IPS_GetInstanceListByModuleID("{F99BF07D-CECA-438B-A497-E4B55F139D37}");
			if(sizeof($ids) > 0) {
				$clientIDs = json_decode(IPS_GetProperty($ids[0], "ClientIDs"), true);
				$found = false;
				foreach($clientIDs as $index => $clientID) {
					if($clientID['ClientID'] == $WebOAuth) {
						if($clientID['TargetID'] == $this->InstanceID)
							return;
						$clientIDs[$index]['TargetID'] = $this->InstanceID;
						$found = true;
					}
				}
				if(!$found) {
					$clientIDs[] = Array("ClientID" => $WebOAuth, "TargetID" => $this->InstanceID);
				}
				IPS_SetProperty($ids[0], "ClientIDs", json_encode($clientIDs));
				IPS_ApplyChanges($ids[0]);
			}
		}*/
	
		/**
		* This function will be called by the register button on the property page!
		*/
		public function Register() {
			
			//Return everything which will open the browser
			return $this->APIBASE."/oauth/token?grant_type=password";
			if ($this->FetchAccessToken()) {
				return "Erfolgreich verbunden";
			} else return "Fehler";
			
		}
		
		private function FetchRefreshToken($code) {
			
			$this->SendDebug("FetchRefreshToken", "Use Authentication Code to get our precious Refresh Token!", 0);
			
			//Exchange our Authentication Code for a permanent Refresh Token and a temporary Access Token
			$options = array(
				'http' => array(
					'header' => "Content-Type: application/x-www-form-urlencoded\r\nUser-Agent:IP-Symcon\r\n",
					'method'  => "POST",
					'content' => http_build_query(Array("grant_type" => "refesh_token","client_id" => $this->CLIENTID,"client_secret" => $this->CLIENTSECRET,"refresh_token" => "refesh_token"))
				)
			);
			$context = stream_context_create($options);
			$result = file_get_contents($this->APIBASE."/oauth/token?grant_type=refresh_token", false, $context);

			$data = json_decode($result);
			
			if(!isset($data->access_token) || $data->token_type != "bearer") {
				die("Bearer Token expected");
			}
			
			//Save temporary access token
			$this->FetchAccessToken($data->access_token, time() + $data->expires_in);

			//Return RefreshToken
			return $data->refresh_token;

		}
		
		/**
		* This function will be called by the OAuth control. Visibility should be protected!
		*/
		protected function ProcessOAuthData() {

			//Lets assume requests via GET are for code exchange. This might not fit your needs!
			if($_SERVER['REQUEST_METHOD'] == "GET") {
		
				if(!isset($_GET['code'])) {
					die("Authorization Code expected");
				}
				
				$token = $this->FetchRefreshToken($_GET['code']);
				
				$this->SendDebug("ProcessOAuthData", "OK! Let's save the Refresh Token permanently", 0);

				IPS_SetProperty($this->InstanceID, "Token", $token);
				IPS_ApplyChanges($this->InstanceID);
			
			} else {
				
				//Just print raw post data!
				echo file_get_contents("php://input");
				
			}

		}
		
		private function FetchAccessToken($Token = "", $Expires = 0) {
			
			//Exchange our Refresh Token for a temporary Access Token
			if($Token == "" && $Expires == 0) {
				
				//Check if we already have a valid Token in cache
				$data = $this->GetBuffer("AccessToken");
				if($data != "") {
					$data = json_decode($data);
					if(time() < $data->Expires) {
						$this->SendDebug("FetchAccessToken", "OK! Access Token is valid until ".date("d.m.y H:i:s", $data->Expires), 0);
						return $data->Token;
					}
				}

				$this->SendDebug("FetchAccessToken", "Use Refresh Token to get new Access Token!", 0);

				//If we slipped here we need to fetch the access token
				$options = array(
					"http" => array(
						'header' => "Content-Type: application/x-www-form-urlencoded\r\nUser-Agent:IP-Symcon\r\n",
						'method'  => "POST",
						'content' => http_build_query(Array("grant_type" => "password","client_id" => $this->CLIENTID,"client_secret" => $this->CLIENTSECRET,"email" => IPS_GetProperty($this->InstanceID, "user","password" => IPS_GetProperty($this->InstanceID, "password"))
				)
				);
				$context = stream_context_create($options);
				$result = file_get_contents($this->APIBASE."/oauth/token?grant_type=password", false, $context);

				$data = json_decode($result);
				
				if(!isset($data->token_type) || $data->token_type != "Bearer") {
					die("Bearer Token expected");
				}
				
				IPS_SetProperty($this->InstanceID, "Token", $data->access_token);
				IPS_SetProperty($this->InstanceID, "RefreshToken", $data->refresh_token);

				//Update parameters to properly cache it in the next step
				$Token = $data->access_token;
				$Expires = time() + $data->expires_in;
				
				return true;
				//Update Refresh Token if we received one! (This is optional)
				/*
				if(isset($data->refresh_token)) {
					$this->SendDebug("FetchAccessToken", "NEW! Let's save the updated Refresh Token permanently", 0);

					IPS_SetProperty($this->InstanceID, "Token", $data->refresh_token);
					IPS_ApplyChanges($this->InstanceID);
				}*/
				
				
			}
		
	}

?>
