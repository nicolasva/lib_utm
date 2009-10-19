#!/usr/bin/ruby

module IFCONFIG
    class Ifconfig
	def initialize
	end

	def tab_liste_interface_reseau
		tab_interface_reseau = Array.new
		compteur = 0
		affichage_interface_reseau.each_line{ |line|
			if compteur > 0
				tab_interface_reseau_split = line.to_s.strip.split(" ")
				tab_interface_reseau.push(tab_interface_reseau_split[0].to_s.strip)
			end
			compteur = compteur + 1
		}
		tab_interface_reseau
	end

	def tab_liste_interface_reseau_bsd
		liste_interface_reseau_bsd = affichage_interface_reseau_bsd
		tab_liste_interface_reseau_bsd = liste_interface_reseau_bsd.split(" ")

		tab_liste_interface_reseau_bsd
	end

	protected
	def affichage_interface_reseau
		%x[ifconfig -s]
	end

	def affichage_interface_reseau_bsd
		%x[ifconfig -l]
	end
    end
end

module FIREWALL
	class Firewall
		def initialize
		end

		def lect_file_iptables
			%x[cat /Users/nicolas/network/interfaces]
		end

		def register_file_iptables(contenu_interfaces_iptables)
			File.open("/Users/nicolas/network/interfaces", "w+") do |file|
					file.write(contenu_interfaces_iptables)	
			end
		end

		def tab_liste_regles_iptables
			hash1 = Hash.new
			tab_regles_iptables = Array.new
			tab_liste_regle_hash = Array.new
			lect_file_iptables.each_line{ |line|
				tab_regles_iptables.push(line.to_s.strip)
			}

			0.upto(tab_regles_iptables.length-1){ |i|
				tab_split_iptables = tab_regles_iptables[i].split(" ")
				1.upto(tab_split_iptables.length-1){ |e|
					hash1[tab_split_iptables[e].to_s.strip] = tab_split_iptables[e+1].to_s.strip
					e = e + 1	
				}
				tab_liste_regle_hash.push(hash1)
			}
			tab_liste_regle_hash
		end
	end
end
module FILESYSTEM
	class Filesystem
		def initialize(list_file_system)
			@list_file_system = list_file_system
		end
		
		def tab_liste_file_system
			tab_liste_file_system = Array.new
			parcours_file_system.each_line{ |liste_file_system|
				if liste_file_system.to_s.strip.scan(/^.{1,}\..{1,}$/) == Array.new
					tab_liste_file_system.push(liste_file_system.to_s.strip)
				end
			}
			tab_liste_file_system
		end

		protected
		def parcours_file_system
			%x[ls #{@list_file_system}]
		end
	end
end

module USER_GROUPE
	class Groupe
		def initialize(groupe)
			@groupe = groupe
		end

		def groupadd
			system("groupadd #{@groupe}")
		end

		def groupmod(new_name_groupe)
			system("groupmod #{@groupe} -n #{new_name_groupe}")
		end

		def groupdel
			system("groupdel #{@groupe}")
		end
	end

	class User
		def initialize
		end

		def add_user(user,groupe,repertoire_perso,password_crypt,partage_public)
			liste_groupe_add = ""
			0.upto(groupe.length-1){ |i|
				if i < groupe.length-1
					liste_groupe_add = "#{groupe[i]},"
				else
					liste_groupe_add = "#{groupe[i]}"
				end
			}

			creation_repertoire_home(repertoire_perso)
		    	creation_repetoir_public_html(repertoire_perso,user) if partage_public.to_i == 1
			system("useradd #{user} #{liste_groupe_add.empty? ? "" : "-G #{liste_groupe_add}"} #{repertoire_perso.empty? ?  "" : "-d #{repertoire_perso}"} -p #{password_crypt}")
		end

		def tab_gener_password_aleatoire
			hash_password_aleatoire = Hash.new
			tab_password_aleatoire = gener_password_aleatoire.split(" ")
			hash_password_aleatoire["password"] = tab_password_aleatoire[0]
			hash_password_aleatoire["password_crypt"] = tab_password_aleatoire[1]
			hash_password_aleatoire
		end

		def userdel(user)
			system("userdel #{user}")
		end

		private
		def gener_password_aleatoire
			%x["makepasswd"]
		end

		def creation_repetoir_public_html(repertoire_perso,user)
			system("mkdir #{repertoire_perso}/#{user}/public_html/")
		end

		def creation_repertoire_home(repertoire_perso)
			system("mkdir #{repertoire_perso}")
		end
	end
end

module DNS
	class Dns_config
		def initialize
		end

		def lect_file_config_dns
			%x[cat /Users/nicolas/bind/named.conf.local]
		end

		def register_file_DNS_conf_expert(contenu_file_dns_conf)	
			File.open("/Users/nicolas/bind/named.conf.local", "w+") do |file|
					file.write(contenu_file_dns_conf)	
			end
		end

		def recup_info_config_dns
			tab_recup_info_config_dns_file = Array.new
			tab_final_hachage = Array.new

			lect_file_config_dns.each_line{ |line|
				tab_recup_info_config_dns_file.push(line)
			}

			0.upto(tab_recup_info_config_dns_file.length-1){ |i|	
				if tab_recup_info_config_dns_file[i].to_s.strip.scan(/^zone(.{1,})\{$/) != Array.new
					hash1 = Hash.new
					hash1["nom_zone"] = tab_recup_info_config_dns_file[i].to_s.strip.scan(/^zone(.{1,})\{$/) 
					while tab_recup_info_config_dns_file[i].to_s.strip != "};"	
						i = i + 1
						tab_recup_info_config_dns_file_split = tab_recup_info_config_dns_file[i].to_s.strip.split(" ")
						hash1[tab_recup_info_config_dns_file_split[0].to_s.strip] = tab_recup_info_config_dns_file_split[1].to_s.strip
					end
					tab_final_hachage.push(hash1)
				end
			}
			tab_final_hachage
		end

		def update_info_config_dns(nom_zone,type_zone_local,notify_zone_local,file_zone_local,nom_zone_inverse,type_zone_inverse,notify_zone_inverse,file_zone_inverse)
				contenu_fichier_conf_dns = "zone '#{nom_zone}' {
							   type #{type_zone_local};
							   notify #{notify_zone_local};
							   file '#{file_zone_local}';
							   allow-update { key rndc-key; };
							   };\n\n
							   
							   zone '#{nom_zone_inverse}' {
							   type #{type_zone_inverse};
							   notify #{notify_zone_inverse};
							   allow-update { key rndc-key; };
							   };"

			File.open("/Users/nicolas/bind/named.conf.local", "w+") do |file|
					file.write(contenu_fichier_conf_dns)	
			end
		end
	end

	class DNS_database
		def initialize
		end

		def lect_file_DB_dns
			%x[cat /Users/nicolas/bind/db.nicolas.fr]
		end

		def recup_database_DB_dns
			hash = Hash.new
			compteur = 0
			lect_file_DB_dns.each_line{ |line|
				if compteur > 10 && line.to_s.strip.scan(/^\$TTL(.{1,})$/) == Array.new && line.to_s.strip.scan(/^TXT(.{1,})$/) == Array.new
					tab_file_DB_dns = line.to_s.strip.split(" ")
					hash[tab_file_DB_dns[0]] = tab_file_DB_dns[2]					
				end
				compteur = compteur + 1
			}
			hash
		end

		def sup_database_DB_dns(nom_machine)
			tab_contenu_DB_dns = Array.new
			compteur = 0

			lect_file_DB_dns.each_line{ |line|	
					tab_contenu_DB_dns.push(line.to_s)
			}

			0.upto(tab_contenu_DB_dns.length-1){ |i|
					tab_contenu_DB_dns_split = tab_contenu_DB_dns[i].to_s.strip.split(" ")
					if tab_contenu_DB_dns_split[0].to_s.strip == nom_machine.to_s.strip
						tab_contenu_DB_dns.delete_at(i)
						if tab_contenu_DB_dns[i+1].to_s.strip.scan(/^TXT(.{1,})$/) != Array.new
							tab_contenu_DB_dns[i+1].delete_at(i+1)
						end
					end
			}


			File.open("/Users/nicolas/bind/db.nicolas.fr", "w+") do |file|
				0.upto(tab_contenu_DB_dns.length-1){ |i|
					file.write(tab_contenu_DB_dns[i])	
				}
			end
		end

		def recup_info_db_dns_pour_modif(nom_machine)
			tab_file_DB_dns = Array.new
			hash1 = Hash.new
			lect_file_DB_dns.each_line{ |line|
				tab_file_DB_dns.push(line)
			}

			0.upto(tab_file_DB_dns.length-1){ |i|
				tab_file_DB_dns_split = tab_file_DB_dns[i].to_s.strip.split(" ")
				if tab_file_DB_dns_split[0].to_s.strip == nom_machine.to_s.strip
					hash1["nom_machine"] = tab_file_DB_dns_split[0]
					hash1["ip_machine"] = tab_file_DB_dns_split[2]
				end	
			}
			hash1
		end

		def update_db_dns_file(nom_machine_hide,nom_machine,ip_machine)
			tab_file_DB_dns = Array.new

			lect_file_DB_dns.each_line{ |line|
				tab_file_DB_dns.push(line)
			}

			0.upto(tab_file_DB_dns.length-1){ |i|
				tab_file_DB_dns_split = tab_file_DB_dns[i].to_s.strip.split(" ")
				if tab_file_DB_dns_split[0].to_s.strip == nom_machine_hide.to_s.strip 
					tab_file_DB_dns[i] = "#{nom_machine}	A	#{ip_machine}"
				end
			}

			File.open("/Users/nicolas/bind/db.nicolas.fr", "w+") do |file|
				0.upto(tab_file_DB_dns.length-1){ |i|
					file.write("#{tab_file_DB_dns[i].to_s.strip}\n")	
				}
			end
		end
	end
end

module DHCP
	class Dhcp
		def initialize
		end

		def lect_file_dhcp
			%x[cat /Users/nicolas/dhcpd.conf]
		end

		def register_file_DHCP_expert(contenu_file_dhcp)	
			File.open("/Users/nicolas/bind/dhcpd.conf.local", "w+") do |file|
					file.write(contenu_file_dhcp)	
			end
		end

		def recup_donnes_dhcp(nom_colonne_recup)
			hash1 = Hash.new
			tab_donnes_dhcp = Array.new
			lect_file_dhcp.each_line{ |line|
				tab_donnes_dhcp.push(line)
			}	

			0.upto(tab_donnes_dhcp.length-1){ |i|
				tab_detail_donnes_dhcp_recup = tab_donnes_dhcp.to_s.strip.split(" ")
			
				0.upto(tab_detail_donnes_dhcp_recup.length-1){ |e|
					if nom_colonne_recup.to_s == tab_detail_donnes_dhcp_recup[e].to_s.strip
						hash1[nom_colonne_recup.to_s] = tab_detail_donnes_dhcp_recup[e+1].to_s.strip
						#hash1["domain-name-servers"] = tab_detail_donnes_dhcp_recup[e+1].strip

					end
				}	
			}

			hash1
		end

		def enregistrement_update_dhcp(ddns_update_style,domain_name_servers,subnet,netmask,domain_name,routers,subnet_mask,broadcast_address,premier_range,deuxieme_range,default_lease_time,max_lease_time,ddns_updates)
				contenu_fichier_configuration_dhcp = "ddns-update-style #{ddns_update_style};
								      authoritative;
								      deny duplicates;
								      ignore declines;
								      option domain-name-servers #{domain_name_servers};
								      subnet #{subnet} netmask #{netmask} {
								      option domain-name '#{domain_name}';
								      option routers #{routers};
								      option subnet-mask #{subnet_mask};
								      option broadcast-address #{broadcast_address};
								      range #{premier_range} #{deuxieme_range};
								      default-lease-time #{default_lease_time};
								      max-lease-time #{max_lease_time};
								      }
								      ddns-updates #{ddns_updates};
								      ddns-domainname '#{domain_name}';
								      ddns-rev-domainname 'in-addr.arpa';
								      include '/etc/bind/rndc.key';
								      zone nicolas.fr {
								      primary 192.168.2.1;
								      key rndc-key;
								      }
								      zone 2.169.192.in-addr.arpa {
								      primary 192.168.2.1;
								      key rndc-key;
								      }"
				
			File.open("/Users/nicolas/dhcpd.conf", "w+") do |file|
				file.write(contenu_fichier_configuration_dhcp)
			end
		end	
	end
end

module SAMBA
	class Samba
		def initialize
		end

		def lect_file_samba
			%x[cat /Users/nicolas/smb.conf]
		end

		def admin_samba_general
			lect_file_samba	
		end

		def update_modification_samba_general(fichier_samba)
			File.open("/Users/nicolas/smb.conf", "w+") do |file|
				file.write(fichier_samba)
			end
		end

		def liste_partage_samba
			tab_liste_partage_samba = Array.new
			tab_lecture_partage_samba_valid = Array.new
			lect_file_samba.each{ |line|
				tab_liste_partage_samba.push(line.strip)		
			}

			0.upto(tab_liste_partage_samba.length-1){ |i|
				if tab_liste_partage_samba[i].to_s.strip.scan(/^\[(.{1,})\]$/) != Array.new && tab_liste_partage_samba[i].to_s.strip != "[global]" && tab_liste_partage_samba[i].to_s.strip != "[homes]" && tab_liste_partage_samba[i].to_s.strip != "[netlogon]" && tab_liste_partage_samba[i].to_s.strip != "[profiles]" && tab_liste_partage_samba[i].to_s.strip != "[Tous]" && tab_liste_partage_samba[i].to_s.strip != "[printers]" && tab_liste_partage_samba[i] != "[print$]"
					tab_lecture_partage_samba_valid.push(tab_liste_partage_samba[i].to_s.strip)
				end
			}

			tab_lecture_partage_samba_valid
		end

		def ajout_partage_samba(nom_partage,comment,path,printable,writable,browseable,choix_public,share_modes,guest_ok,droit_create_mask,droit_directory_mask,valid_users)
			contenu_partage_ajoute = "[#{nom_partage}]
			comment = #{comment}
			path = #{path}
			printable = #{printable.to_i == 1 ? 'yes' : 'no'}
			writable = #{writable.to_i == 1 ? 'yes' : 'no'}
			browseable = #{browseable.to_i == 1 ? 'yes' : 'no'}
			public = #{choix_public.to_i == 1 ? 'yes' : 'no'}
			share modes = #{share_modes.to_i == 1 ? 'yes' : 'no'}
			guest ok = #{guest_ok.to_i == 1 ? 'yes' : 'no'}
			create mask = 00#{droit_create_mask}
			directory mask = 00#{droit_directory_mask}
			#{valid_users.empty? ? "" : 'valid users = '+valid_users}\n\n"
			
			File.open("/Users/nicolas/smb.conf", "a+") do |file|
				file.write(contenu_partage_ajoute)
			end
		end

		def recup_info_partage_samba_update(nom_partage)
			hash1 = Hash.new
			tab_liste_info_partage_samba = Array.new
			lect_file_samba.each_line{ |liste_contenu_samba|
				#if liste_contenu_samba.to_s.strip = nom_partage.to_s.strip
					#hash1["nom_partage"] = 
				#end
				tab_liste_info_partage_samba.push(liste_contenu_samba.to_s.strip)
			}

			0.upto(tab_liste_info_partage_samba.length-1){ |i|
				if tab_liste_info_partage_samba[i].to_s.strip == nom_partage.to_s.strip
						hash1["nom_partage"] = nom_partage.to_s.strip
						while !tab_liste_info_partage_samba[i].empty?
							i = i + 1
							tab_contenu_partage_detail = tab_liste_info_partage_samba[i].to_s.strip.split("=")
							hash1[tab_contenu_partage_detail[0].to_s.strip] = tab_contenu_partage_detail[1]
						end
				end
			}

			hash1
		end

		def modification_partage_samba(nom_evenement_hide,nom_evenement,comment,path,printable,writable,browseable,choix_public,share_modes,guest_ok,valid_users,droit_create_mask,droit_directory_mask)
			tab_contenu_samba = Array.new
			lect_file_samba.each_line{ |line|
				tab_contenu_samba.push(line.to_s.strip)
			}		

		     0.upto(tab_contenu_samba.length-1){ |i|
				if nom_evenement_hide.to_s.strip == tab_contenu_samba[i].to_s.strip
					tab_contenu_samba[i] = "[#{nom_evenement}]"
					i = i + 1
					tab_contenu_samba[i] = "comment = #{comment}"
					i = i + 1
					tab_contenu_samba[i] = "path = #{path}"
					i = i + 1
					tab_contenu_samba[i] = "printable = #{printable.to_i == 1 ? 'yes' : 'no'}"
					i = i + 1
					tab_contenu_samba[i] = "writable = #{writable.to_i == 1 ? 'yes' : 'no'}"
					i = i + 1
					tab_contenu_samba[i] = "browseable = #{browseable.to_i == 1 ? 'yes' : 'no'}"
					i = i + 1
					tab_contenu_samba[i] = "public = #{choix_public.to_i == 1 ? 'yes' : 'no'}"
					i = i + 1
					tab_contenu_samba[i] = "guest ok = #{guest_ok.to_i == 1 ? 'yes' : 'no'}"
					i = i + 1
					tab_contenu_samba[i] = "share modes = #{share_modes.to_i == 1 ? 'yes' : 'no'}"
					i = i + 1
					tab_contenu_samba[i] = "create mask = 00#{droit_create_mask}"
					i = i + 1	
					if valid_users.empty?
					tab_contenu_samba[i] = "directory mask = 00#{droit_directory_mask}\n\n"
					else
					tab_contenu_samba[i] = "directory mask = 00#{droit_directory_mask}"
					i = i + 1
					tab_contenu_samba[i] = "valid users = #{valid_users}\n\n"
					end
				end
			}

			File.open("/Users/nicolas/smb.conf", "w") do |file|
				0.upto(tab_contenu_samba.length-1){ |i|
					file.write("#{tab_contenu_samba[i]}\n")
				}
			end

		end

		def sup_partage_samba(nom_partage)
			tab_contenu_samba = Array.new
			lect_file_samba.each_line{ |line|
				tab_contenu_samba.push(line.to_s.strip)
			}

			0.upto(tab_contenu_samba.length-1){ |i|
				if tab_contenu_samba[i].to_s.strip == nom_partage.to_s.strip
					while !tab_contenu_samba[i].empty?
						tab_contenu_samba.delete_at(i)
						i = i + 1
					end
				end
			}

			File.open("/Users/nicolas/smb.conf", "w") do |file|
				0.upto(tab_contenu_samba.length-1){ |i|
					file.write("#{tab_contenu_samba[i]}\n")
				}
			end
		end

		def reste_form_add_iptables
			render(:update){ |page|
				if params[:id].to_s == 'forward'
					
				else
				end
			}
		end
	end
end

