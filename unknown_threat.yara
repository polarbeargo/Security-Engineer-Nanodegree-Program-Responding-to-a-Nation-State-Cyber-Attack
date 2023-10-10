rule SSH_detector {

        meta:

                Author = "@hsinwenchang"

                Description = "This rule detects the presence of SSH-One malware"

        strings:

		$rule = "http://darkl0rd.com"

                

        condition:

                all of them



}