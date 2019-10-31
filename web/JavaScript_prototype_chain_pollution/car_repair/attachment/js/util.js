const urlParams = new URLSearchParams(window.location.search)//返回查询部分?
const h = location.hash.slice(1)//返回锚部分#
const bugatti = new Car('Bugatti', 'T35', 'green', 'assets/images/bugatti.png')
const porsche = new Car('Porsche', '911', 'yellow', 'assets/images/porsche.png')

const cars = [bugatti, porsche]

porsche.repair = () => {
    if(!bugatti.isStarted()){
        infobox(`Not so fast. Repair the other car first!`)
    }
    else if($.md5(porsche) == '9cdfb439c7876e703e307864c9167a15'){
        if(urlParams.has('help')) {
            repairWithHelper(urlParams.get('help'))
        }
    }
    else{
        infobox(`Repairing this is not that easy.`)
    }
}
porsche.ignition = () => {
    infobox(`Hmm ... WTF!`)
}

$(document).ready(() => {
    const [car] = cars
    $('.fa-power-off').click(() => car.powerOn())
    $('.fa-car').click(() => car.info())
    $('.fa-lightbulb-o').click(() => car.light())
    $('.fa-battery-quarter').click(() => car.battery())
    $('.fa-key').click(() => car.ignition())
    $('.fa-wrench').click(() => car.repair())
    
    $('.fa-step-forward').click(() => nextCar())

    if(h.includes('Bugatti'))
        autoStart(bugatti)
    if(h.includes('Porsche'))
        autoStart(porsche)
})


const nextCar = () => {
    cars.push(cars.shift())
    $(".image").attr('src', cars[0].pic);
}


const autoStart = (car) => {
    car.repair()
    car.ignition()
    car.powerOn()
}


const repairWithHelper = (src) => {
    /* who needs csp anyways !? */
    urlRegx = /^\w{4,5}:\/\/car-repair-shop\.fluxfingersforfuture\.fluxfingers\.net\/[\w\d]+\/.+\.js$/;
    if (urlRegx.test(src)) {
        let s = document.createElement('script')
        s.src = src
        $('head').append(s)
    }
}


const infobox = (text) => {
    $('a').css({'pointer-events': 'none', 'border': 'none'})
    $('.infobox').addClass('infoAnimate')
        .text(text)
        .on('animationend', function() {
            $(this).removeClass('infoAnimate')
            $('a').css({'pointer-events': 'all', 'border': 'solid 1px rgba(255, 255, 255, .25)'})
    })
    
}