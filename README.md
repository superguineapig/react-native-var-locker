# react-native-var-locker
Simplified map-like immutable data structure that uses device keychain to encrypt values in RAM

# What?
So, I had a goofy idea about dealing with sensitive data at runtime:
> What if I could encrypt a variable so the raw value never sits in memory

And so *SecureMap* and *VarLocker* were born.

## Um...
Yeah, I don't know if this is even practical. More to come later.

# NOTE
This repo is **pre-alpha** right now, and is missing documentation, examples, directory structure, package configs, deps, etc.
I'll add more when I get to it. Feel free to watch, but you might be waiting a while before anything of substance materializes ;-)

# Credits
The stuff here is really just a couple of Javascript wrappers that build on top of https://github.com/amitaymolko/react-native-rsa-native

That's where all the real magic happens. Go check it out if you're looking for general native encryption using device keychains. It's pretty cool.

# Stay tuned...
