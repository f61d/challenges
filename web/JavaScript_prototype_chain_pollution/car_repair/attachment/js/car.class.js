class Car {
    constructor(type, model, color, pic, key="") {
        this.type = type
        this.model = model
        this.color = color
        this.key = key
        this.pic = pic

        let started = false
        this.start = () => {
            started = true
        }
        this.isStarted = () => {
            return started
        }
    }
    powerOn() {
        if (this.isStarted()) {
            infobox(`Well Done!`)
            nextCar()

        } else {
            $('.chargeup')[0].play()
        }
    }
    info() {
        infobox(`This car is a ${this.type} ${this.model} in ${this.color}. It looks very nice! But it seems to be broken ...`)
    }
    repair() {
        if(urlParams.has('repair')) {
            $.extend(true, this, JSON.parse(urlParams.get('repair')))
        }
    }
    light() {
        infobox(`You turn on the lights ... Nothing happens.`)
    }
    battery() {
        infobox(`Hmmm, the battery is almost empty ... Maybe i can repair this somehow.`)
    }
    ignition() {
        if (this.key == "") {
            infobox(`Looks like the key got lost. No wonder the car is not starting ...`)
        }
        if (this.key == "馃攽") {
            infobox(`The car started!`)
            this.start()
        }
    }
}