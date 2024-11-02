import { NextFunction, Request, Response } from "express";

const asynchandler =
  (
    reqhandler: (
      req: Request,
      res: Response,
      next: NextFunction
    ) => Promise<any>
  ) =>
  (req: Request, res: Response, next: NextFunction) => {
    try {
      return reqhandler(req, res, next);
    } catch (error) {
      next(error);
    }
  };

export default asynchandler;
