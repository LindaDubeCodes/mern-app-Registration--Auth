import pkg from 'jsonwebtoken';
const { jwt } = pkg;

export default async function Auth(req, res, next) {
    try {
        const token = req.headers.authorization.split(" ")[1];

        //retrieve user details to logged in user
        const decodedToken = await jwt.verify(token, ENV.JWT_SECRET);

        req.user = decodedToken;


        next()

    } catch (error) {
        res.status(401).json({ error: "Authentication Failed!" })
    }

}
export function localVariables(req, res, next) {
    req.app.locals = {
        OTP: null,
        resetSession: false
    }
    next()
}
