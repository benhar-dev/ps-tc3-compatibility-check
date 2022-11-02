class Hello {
# properties
[string]$person

# Default constructor
Hello(){}

# Constructor
Hello(
[string]$m
){
$this.person=$m
}

# method
[string]Greetings(){
return "Hello {0}" -f $this.person
}

}

Class Computer {
    [String]$Name
}