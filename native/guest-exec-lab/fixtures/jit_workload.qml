import QtQml

QtObject {
    Component.onCompleted: {
        const start = Date.now();
        let sum = 0;
        for (let i = 0; i < 200; ++i) {
            const fn = new Function("x", "return x * 2 + " + i + ";");
            for (let j = 0; j < 200; ++j) sum += fn(j);
        }
        console.log("MD_QML_JIT milliseconds=" + (Date.now() - start) + " sum=" + sum);
        Qt.exit(sum === 11940000 ? 0 : 1);
    }
}
