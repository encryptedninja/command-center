Update package list
`sudo apt update && sudo apt upgrade`

Install i3 and essential components
`sudo apt install -y i3 i3status i3lock dmenu rofi xbacklight feh thunar xfce4-appfinder network-manager network-manager-gnome xfce4-terminal`

(Optional) Install picom for compositing
`sudo apt install -y picom`

Install Hack Nerd Font (for icons in i3bar/workspaces)

*I don't use it but leave it here for reference.*
* `mkdir -p ~/.local/share/fonts`
* `cd ~/.local/share/fonts`
* `wget https://github.com/ryanoasis/nerd-fonts/releases/latest/download/Hack.zip`
* `unzip Hack.zip && rm Hack.zip`
* `fc-cache -fv`
