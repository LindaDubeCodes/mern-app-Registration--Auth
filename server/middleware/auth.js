import pkg from 'jsonwebtoken';
const { Jwt } = pkg;

export default async function Auth(req, res, next) {
    try {
        const token = req.headers.authorization.split(" ")[1];

        //retrieve user details to logged in user
        const decodedToken = await Jwt.verify(token, Env.JWT_SECRET);

        req.user = decodedToken;
        res.json(decodedToken);

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
